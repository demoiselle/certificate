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
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.policies;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigPolicyQualifierInfoURL;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignaturePolicyId;
import br.gov.frameworkdemoiselle.certificate.signer.util.ValidadorUtil;
import br.gov.frameworkdemoiselle.certificate.signer.util.ValidadorUtil.CertPathEncoding;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 * Implementa a Política ICP-Brasil
 *
 * POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO
 * CMS versão 1.0
 *
 * definida no documento: REQUISITOS DAS POLÍTICAS DE ASSINATURA DIGITAL NA
 * ICP-BRASIL - DOC-ICP-15.03 - Versão 2.0 - 05 de abril de 2010
 *
 */
public class ADRBCMS_1_0 {

    private static final Logger logger = Logger.getLogger(ADRBCMS_1_0.class.getName());
    private final int keySize = 1024;

    public SignaturePolicyId getSignaturePolicyId() {
        SignaturePolicyId signaturePolicyId = new SignaturePolicyId();
        signaturePolicyId.setHash(new byte[]{-76, 110, 85, 63, -101, 72, 58, -104, 88, 91, -26, -27, -81, 61, -28, 105, -50, -95, -115, -44});
        signaturePolicyId.setHashAlgorithm(SignerAlgorithmEnum.SHA1withDSA.getOIDAlgorithmHash());
        signaturePolicyId.setSigPolicyId(OIDICPBrasil.POLICY_ID_AD_RB_CMS_V_1_0);
        signaturePolicyId.addSigPolicyQualifiers(new SigPolicyQualifierInfoURL("http://www.iti.gov.br/twiki/pub/Certificacao/DocIcp/DOC-ICP-15.03.pdf"));
        return signaturePolicyId;
    }

    public void validate(byte[] content, byte[] contentSigned) {

        if (contentSigned == null || contentSigned.length == 0) {
            throw new SignerException("O conteúdo assinado está vazio");
        }

        //Validando a integridade do arquivo
        CMSSignedData cmsSignedData = null;
        try {
            if (content == null) {
                cmsSignedData = new CMSSignedData(contentSigned);
            } else {
                cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(content), contentSigned);
            }
        } catch (CMSException exception) {
            throw new SignerException("Bytes inválidos encontrados no pacote PKCS7", exception);
        }

        try {
            Store certStore = cmsSignedData.getCertificates();
            SignerInformationStore signers = cmsSignedData.getSignerInfos();
            Iterator<?> it = signers.getSigners().iterator();

            //Recupera o certificado e a chave pública da assinatura
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection<?> certCollection = certStore.getMatches(signer.getSID());

                Iterator<?> certIt = certCollection.iterator();
                X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();

                if (!certCollection.isEmpty()) {
                    X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
                }

                //Realiza a validação dos atributos
                AttributeTable signedAttributesTable = signer.getSignedAttributes();

                //Validando o atributo ContentType
                org.bouncycastle.asn1.cms.Attribute attributeContentType = signedAttributesTable.get(CMSAttributes.contentType);
                if (attributeContentType == null) {
                    throw new SignerException("O pacote PKCS7 não contém o atributo \"ContentType\"");
                }

                if (!attributeContentType.getAttrValues().getObjectAt(0).equals(ContentInfo.data)) {
                    throw new SignerException("\"ContentType\" não é do tipo \"DATA\"");
                }

                //Com o atributo ContentType válido, extrair o conteúdo assinado, caso possua o conteúdo anexado
                CMSTypedData contentProcessable = cmsSignedData.getSignedContent();
                if (contentProcessable != null) {
                    content = (byte[]) contentProcessable.getContent();
                }

                //Validando o atributo MessageDigest
                org.bouncycastle.asn1.cms.Attribute attributeMessageDigest = signedAttributesTable.get(CMSAttributes.messageDigest);
                if (attributeMessageDigest == null) {
                    throw new SignerException("O pacote PKCS7 não possui o atributo \"MessageDigest\"");
                }

                Object primitive = attributeMessageDigest.getAttrValues().getObjectAt(0).toASN1Primitive();
                ASN1OctetString octeto = ASN1OctetString.getInstance(primitive);
                byte[] hashContentSigned = octeto.getOctets();

                String algorithm = SignerAlgorithmEnum.getSignerOIDAlgorithmHashEnum(signer.getDigestAlgorithmID().getAlgorithm().getId()).getAlgorithmHash();
                if (!algorithm.equals(DigestAlgorithmEnum.SHA_1.getAlgorithm())) {
                    throw new SignerException("Algoritmo de resumo inválido para esta política");
                }

                Digest digest = DigestFactory.getInstance().factoryDefault();
                digest.setAlgorithm(algorithm);
                byte[] hashContent = digest.digest(content);
                if (!MessageDigest.isEqual(hashContentSigned, hashContent)) {
                    throw new SignerException("O hash é diferente.");
                }

                JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
                SignerInformationVerifier verifier = builder.build(certificateHolder);
                signer.verify(verifier);

                // Valida a cadeia de certificação de um arquivo assinado
                ValidadorUtil.validate(contentSigned, OIDICPBrasil.POLICY_ID_AD_RB_CMS_V_1_0, CertPathEncoding.PKCS7);

                //Valida o período de validade
                org.bouncycastle.asn1.cms.Attribute attributeSigningTime = signedAttributesTable.get(CMSAttributes.signingTime);
                ASN1Set valorDateSigner = attributeSigningTime.getAttrValues();
                DERSet derSet = (DERSet) valorDateSigner.toASN1Primitive();
                ASN1UTCTime utcTime = (ASN1UTCTime) derSet.getObjectAt(0);
                Date dataSigner = utcTime.getAdjustedDate();

                //Para a versão 1.0, o período para assinatura desta PA é de 31/10/2008 a 31/12/2014.
                Calendar calendar = GregorianCalendar.getInstance();
                calendar.set(2008, Calendar.OCTOBER, 31, 0, 0, 0);
                Date beforeDate = calendar.getTime();

                calendar.set(2014, Calendar.DECEMBER, 31, 23, 59, 59);
                Date afterDate = calendar.getTime();

                logger.log(Level.INFO, "Verificando o período de validade da política");
                SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy - hh:mm:ss");

                if (dataSigner != null) {
                    if (dataSigner.before(beforeDate)) {
                        throw new SignerException("Esta política não é válida antes de" + sdf.format(beforeDate));
                    }
                    if (dataSigner.after(afterDate)) {
                        throw new SignerException("Esta política não é válida depois de" + sdf.format(afterDate));
                    }
                } else {
                    throw new SignerException("O atributo \"SigningTime\" existe no pacote PKCS7, mas ele é nulo.");
                }
            }
        } catch (SignerException ex) {
            throw new SignerException("Ocorreu um erro ao verificar o certificado e chave pública do pacote PKCS7", ex);
        } catch (CMSException e) {
            throw new SignerException("A assinatura é inválida.", e);
        } catch (CertificateException | OperatorCreationException | ParseException ex) {
            throw new SignerException(ex);
        }
    }

    /**
     * Efetua a validação da politica para um determinado certificado no momento
     * da assinatura
     *
     * @param certificate O certificado a ser validado
     * @param privateKey A chave privada a ser validada
     */
    public void validate(X509Certificate certificate, PrivateKey privateKey) {

        // O tamanho mínimo de chaves para criação de assinaturas segundo estaPA é de:
        // para a versão 1.0: 1024 bits
        // para a versão 1.1: 1024 bits
        // para a versão 2.0: 2048 bits
        // para a versão 2.1: 2048 bits
        if (((RSAKey) certificate.getPublicKey()).getModulus().bitLength() < keySize) {
            throw new SignerException("O tamanho mínimo da chave privada deve ser de " + keySize + " bits");
        }

        /*
         * Assinaturas digitais geradas segundo esta Política de Assinatura deverão ser criadas com chave privada associada ao certificado ICP-Brasil
         * tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100)
         * tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100)
         * tipo A3 (do OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100)
         * tipo A4 (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04.
         */
        ValidadorUtil.validate(certificate);

        // TODO Implementar a validação do caminho de certificação para o certificado digital a ser utilizado na assinatura
    }

    public SignerAlgorithmEnum getSignerAlgorithm() {
        return SignerAlgorithmEnum.SHA1withRSA;
    }

//    @Override
//    public SigningCertificate getSigningCertificateAttribute(X509Certificate certificate) {
//        return new SigningCertificate(certificate);
//    }
}
