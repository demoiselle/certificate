package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.TimeStampGenerator;
import br.gov.frameworkdemoiselle.timestamp.connector.Connector;
import br.gov.frameworkdemoiselle.timestamp.connector.ConnectorFactory;
import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import br.gov.frameworkdemoiselle.timestamp.enumeration.PKIFailureInfo;
import br.gov.frameworkdemoiselle.timestamp.enumeration.PKIStatus;
import br.gov.frameworkdemoiselle.timestamp.exception.TimestampException;
import br.gov.frameworkdemoiselle.timestamp.signer.RequestSigner;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class TimestampGeneratorImpl implements TimeStampGenerator {

    private static final Logger logger = LoggerFactory.getLogger(TimestampGeneratorImpl.class);

    private InputStream inputStream = null;
    private Timestamp timestamp;
    private TimeStampRequest timeStampRequest;
    private TimeStampResponse timeStampResponse;

    private byte[] content;
    private PrivateKey privateKey;
    private Certificate[] certificates;

    @Override
    public void initialize(byte[] content, PrivateKey privateKey, Certificate[] certificates) {
        this.content = content;
        this.privateKey = privateKey;
        this.certificates = certificates;
    }

    /**
     * Cria uma requisição de carimbo de tempo assinada pelo usuario
     *
     * @return Uma requisicao de carimbo de tempo
     * @throws TimestampException
     * @throws IOException
     */
    private byte[] createRequest() throws TimestampException, IOException {
        logger.info("Gerando o digest do conteudo");
        Digest digest = DigestFactory.getInstance().factoryDefault();
        digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
        byte[] hashedMessage = digest.digest(content);
        logger.info(Base64.toBase64String(hashedMessage));

        logger.info("Montando a requisicao para o carimbador de tempo");
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("2.16.76.1.6.2"));
        timeStampRequestGenerator.setCertReq(true);
        timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, hashedMessage, BigInteger.valueOf(100));
        byte request[] = timeStampRequest.getEncoded();

        logger.info("Efetuando a  assinatura do conteudo");
        RequestSigner requestSigner = new RequestSigner();
        byte[] signedRequest = requestSigner.signRequest(privateKey, certificates, request);
        return signedRequest;
    }

    /**
     * Envia a requisicao de carimbo de tempo para um servidor de carimbo de
     * tempo
     *
     * @return O carimbo de tempo retornado pelo servidor
     */
    @Override
    public byte[] generateTimeStamp() throws SignerException {
        try {
            byte[] request = this.createRequest();

            logger.info("Iniciando pedido de carimbo de tempo");
            Connector connector = ConnectorFactory.buildConnector(ConnectionType.SOCKET);
            connector.setHostname("act.serpro.gov.br");
            connector.setPort(318);

            logger.info("Obtendo o response");
            inputStream = connector.connect(request);

            long tempo;
            // Valor do timeout da verificacao de dados disponiveis para leitura
            int timeOut = 3500;
            // Verificando se os 4 bytes iniciais estao disponiveis para leitura
            for (tempo = System.currentTimeMillis() + timeOut; inputStream.available() < 4 && System.currentTimeMillis() < tempo;) {
                try {
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // Lendo tamanho total
            byte[] tamanhoRetorno = new byte[4];
            inputStream.read(tamanhoRetorno, 0, 4);
            int tamanho = new BigInteger(tamanhoRetorno).intValue();

            // Verificando se os bytes na quantidade "tamanho" estao disponiveis
            if (System.currentTimeMillis() < tempo) {
                while (inputStream.available() < tamanho && System.currentTimeMillis() < tempo) {
                    try {
                        Thread.sleep(1L);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                if (System.currentTimeMillis() >= tempo) {
                    logger.error("Erro timeout ao receber dados");
                }
            } else {
                logger.error("Erro timeout ao receber dados");
            }

            // Lendo flag
            byte[] retornoFlag = new byte[1];
            inputStream.read(retornoFlag, 0, 1);
            // tamanho total menos o tamanho da flag
            tamanho -= 1;

            // Lendo dados carimbo
            byte[] retornoCarimboDeTempo = new byte[tamanho];
            inputStream.read(retornoCarimboDeTempo, 0, tamanho);
            timeStampResponse = new TimeStampResponse(retornoCarimboDeTempo);

            logger.info("PKIStatus....: {}", timeStampResponse.getStatus());

            switch (timeStampResponse.getStatus()) {
                case 0: {
                    logger.info(PKIStatus.granted.getMessage());
                    break;
                }
                case 1: {
                    logger.info(PKIStatus.grantedWithMods.getMessage());
                    break;
                }
                case 2: {
                    logger.info(PKIStatus.rejection.getMessage());
                    throw new TimestampException(PKIStatus.rejection.getMessage());
                }
                case 3: {
                    logger.info(PKIStatus.waiting.getMessage());
                    throw new TimestampException(PKIStatus.waiting.getMessage());
                }
                case 4: {
                    logger.info(PKIStatus.revocationWarning.getMessage());
                    throw new TimestampException(PKIStatus.revocationWarning.getMessage());
                }
                case 5: {
                    logger.info(PKIStatus.revocationNotification.getMessage());
                    throw new TimestampException(PKIStatus.revocationNotification.getMessage());
                }
                default: {
                    logger.info(PKIStatus.unknownPKIStatus.getMessage());
                    throw new TimestampException(PKIStatus.unknownPKIStatus.getMessage());
                }
            }

            int failInfo = -1;

            if (timeStampResponse.getFailInfo() != null) {
                failInfo = Integer.parseInt(new String(timeStampResponse.getFailInfo().getBytes()));
            }

            logger.info("FailInfo....: {}", failInfo);

            switch (failInfo) {
                case 0:
                    logger.info(PKIFailureInfo.badAlg.getMessage());
                    break;
                case 2:
                    logger.info(PKIFailureInfo.badRequest.getMessage());
                    break;
                case 5:
                    logger.info(PKIFailureInfo.badDataFormat.getMessage());
                    break;
                case 14:
                    logger.info(PKIFailureInfo.timeNotAvailable.getMessage());
                    break;
                case 15:
                    logger.info(PKIFailureInfo.unacceptedPolicy.getMessage());
                    break;
                case 16:
                    logger.info(PKIFailureInfo.unacceptedExtension.getMessage());
                    break;
                case 17:
                    logger.info(PKIFailureInfo.addInfoNotAvailable.getMessage());
                    break;
                case 25:
                    logger.info(PKIFailureInfo.systemFailure.getMessage());
                    break;
            }

            timeStampResponse.validate(timeStampRequest);
            TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
            timestamp = new Timestamp(timeStampToken);

            if (timeStampToken == null) {
                throw new TimestampException("O Token retornou nulo.");
            }
            connector.close();

            //Imprime os dados do carimbo de tempo
            logger.info(timestamp.toString());

            //Retorna o carimbo de tempo gerado
            return retornoCarimboDeTempo;

        } catch (TimestampException | IOException | NumberFormatException | TSPException e) {
            throw new SignerException(e.getMessage());
        }
    }

    /**
     * Efetua a validacao de um carimbo de tempo
     *
     * @param response O carimbo de tempo a ser validado
     * @throws SignerException
     */
    public void validate(byte[] response) throws SignerException {
        try {
            Security.addProvider(new BouncyCastleProvider());
            TimeStampResponse tsr = new TimeStampResponse(response);
            TimeStampToken timeStampToken = tsr.getTimeStampToken();
            CMSSignedData s = timeStampToken.toCMSSignedData();

            int verified = 0;

            Store certStore = s.getCertificates();
            SignerInformationStore signers = s.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();

            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = certStore.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                    verified++;
                }

                cert.getExtension(new ASN1ObjectIdentifier("2.5.29.31")).getExtnValue();
            }

            logger.info("Assinaturas Verificadas....: {}", verified);
            this.timestamp = new Timestamp(timeStampToken);
        } catch (TSPException | IOException | CMSException | OperatorCreationException | CertificateException ex) {
            throw new SignerException(ex.getMessage());
        }
    }

    /**
     * Valida um carimnbo de tempo e o documento original
     *
     * @param response O carimbo de tempo a ser validado
     * @throws SignerException
     */
    @Override
    public void validateTimeStamp(byte[] response) throws SignerException {
        //Valida a assinatura digital do carimbo de tempo
        this.validate(response);

        //Valida o hash  incluso no carimbo de tempo com hash do arquivo carimbado
        Digest digest = DigestFactory.getInstance().factoryDefault();
        digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
        digest.digest(content);

        if (Arrays.equals(digest.digest(content), this.timestamp.getMessageImprintDigest())) {
            logger.info("Digest do documento conferido com sucesso.");
        } else {
            throw new SignerException("O documento fornecido nao corresponde ao do carimbo de tempo!");
        }
    }
}
