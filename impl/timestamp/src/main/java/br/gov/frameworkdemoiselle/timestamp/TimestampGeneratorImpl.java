/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import br.gov.frameworkdemoiselle.certificate.exception.CertificateCoreException;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.TimeStampGenerator;
import br.gov.frameworkdemoiselle.timestamp.connector.TimeStampOperator;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimestampGeneratorImpl implements TimeStampGenerator {

    private static final Logger logger = LoggerFactory.getLogger(TimestampGeneratorImpl.class);

    private Timestamp timestamp;
    private byte[] content;
    private PrivateKey privateKey;
    private Certificate[] certificates;
    Properties p;

    public TimestampGeneratorImpl() {
        try {
            p = new Properties();
            p.load(this.getClass().getResourceAsStream("/br/gov/frameworkdemoiselle/timestamp/config.properties"));
        } catch (IOException ex) {
            logger.info(ex.getMessage());
        }
    }

    @Override
    public void initialize(byte[] content, PrivateKey privateKey, Certificate[] certificates) throws CertificateCoreException {
        this.content = content;
        this.privateKey = privateKey;
        this.certificates = certificates;
    }

    /**
     * Envia a requisicao de carimbo de tempo para um servidor de carimbo de
     * tempo
     *
     * @return O carimbo de tempo retornado pelo servidor
     */
    @Override
    public byte[] generateTimeStamp() throws CertificateCoreException {
        TimeStampOperator timeStampOperator = new TimeStampOperator();
        byte[] request = timeStampOperator.createRequest(privateKey, certificates, content);
        return timeStampOperator.invoke(request);
    }

    /**
     * Efetua a validacao de um carimbo de tempo
     *
     * @param response O carimbo de tempo a ser validado
     *
     */
    public void validate(byte[] response) throws CertificateCoreException {
        try {
            Security.addProvider(new BouncyCastleProvider());
            TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(response));
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
            throw new CertificateCoreException(ex.getMessage());
        }
    }

    /**
     * Valida um carimnbo de tempo e o documento original
     *
     * @param response O carimbo de tempo a ser validado
     *
     */
    @Override
    public void validateTimeStamp(byte[] response) throws CertificateCoreException {

        //Valida a assinatura digital do carimbo de tempo
        this.validate(response);

        //Valida o hash  incluso no carimbo de tempo com hash do arquivo carimbado
        Digest digest = DigestFactory.getInstance().factoryDefault();
        digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
        digest.digest(content);

        if (Arrays.equals(digest.digest(content), this.timestamp.getMessageImprintDigest())) {
            logger.info("Digest do documento conferido com sucesso.");
        } else {
            throw new CertificateCoreException("O documento fornecido nao corresponde ao do carimbo de tempo!");
        }

    }

}
