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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.SignaturePolicy;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.SignaturePolicyException;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigPolicyQualifierInfoURL;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignaturePolicyId;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigningCertificate;
import br.gov.frameworkdemoiselle.certificate.signer.util.ValidadorUtil;

/**
 * Implementa a Política ICP-Brasil
 *
 * POLÍTICA ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERÊNCIA BÁSICA NO FORMATO
 * CMS versão 2.0
 *
 * definina no documento: REQUISITOS DAS POLÍTICAS DE ASSINATURA DIGITAL NA
 * ICP-BRASIL - DOC-ICP-15.03 - Versão 3.0 - 20 de dezembro de 2011
 *
 * @author SUPST/STDCS
 *
 */
public class ADRBCMS_2_0 implements SignaturePolicy {

    private final int keySize = 2048;

    @Override
    public SignaturePolicyId getSignaturePolicyId() {
        SignaturePolicyId signaturePolicyId = new SignaturePolicyId();
        // TODO: Gerar hash do PDF da política
        signaturePolicyId.setHash(new byte[]{ 83, 17, -26, -50, 85, 102, 92, -121, -10, 8, 94, -15, 28, -126, -6, 63, -79, 52, 28, -83, -25, -104, 30, -39, -11, 29, 62, 86, -34, 95, 106, -83 });
        signaturePolicyId.setHashAlgorithm(SignerAlgorithmEnum.SHA256withRSA.getOIDAlgorithmHash());
        signaturePolicyId.setSigPolicyId(OIDICPBrasil.POLICY_ID_AD_RB_CMS_V_2_0);
        signaturePolicyId.addSigPolicyQualifiers(new SigPolicyQualifierInfoURL("http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_0.der"));
        return signaturePolicyId;
    }

    @Override
    public void validate(byte[] content, byte[] contentSigned) {
        if (contentSigned == null || contentSigned.length == 0) {
            throw new SignaturePolicyException("Content signed is null");
        }

        X509Certificate certificate = null;
        PublicKey publicKey = null;

        // Validando a integridade do arquivo
        CMSSignedData signedData = null;
        try {
            if (content == null) {
                signedData = new CMSSignedData(contentSigned);
            } else {
                signedData = new CMSSignedData(new CMSProcessableByteArray(content), contentSigned);
            }
        } catch (CMSException exception) {
            throw new SignerException("Invalid bytes for a package PKCS7", exception);
        }

        // Validando as informações da assinatura
        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        SignerInformation signerInformation = (SignerInformation) signerInformationStore.getSigners().iterator().next();

        // Retirando o Certificado Digital e a chave Pública da assinatura
        try {
            CertStore certs;
            try {
                Security.addProvider(new BouncyCastleProvider());
                certs = signedData.getCertificatesAndCRLs("Collection", "BC");
                Collection<? extends Certificate> collCertificados = certs.getCertificates(signerInformation.getSID());
                if (!collCertificados.isEmpty()) {
                    certificate = (X509Certificate) collCertificados.iterator().next();
                    publicKey = certificate.getPublicKey();
                }
            } catch (NoSuchAlgorithmException exception) {
                throw new SignerException(exception);
            } catch (NoSuchProviderException exception) {
                throw new SignerException(exception);
            } catch (CMSException exception) {
                throw new SignerException(exception);
            } catch (CertStoreException exception) {
                throw new SignerException(exception);
            }
        } catch (SignerException exception) {
            throw new SignerException("Error on get information about certificates and public keys from a package PKCS7", exception);
        }

        // Validando os atributos assinados
        AttributeTable signedAttributesTable = signerInformation.getSignedAttributes();

        // Validando o atributo ContentType
        org.bouncycastle.asn1.cms.Attribute attributeContentType = signedAttributesTable.get(CMSAttributes.contentType);
        if (attributeContentType == null) {
            throw new SignerException("Package PKCS7 without attribute ContentType");
        }

        if (!attributeContentType.getAttrValues().getObjectAt(0).equals(ContentInfo.data)) {
            throw new SignerException("ContentType isn't a DATA type");
        }

        // Com o atributo ContentType válido, extrair o conteúdo assinado, caso
        // possua o conteúdo atached
        try {
            CMSProcessable contentProcessable = signedData.getSignedContent();
            if (contentProcessable != null) {
                content = (byte[]) contentProcessable.getContent();
            }
        } catch (Exception exception) {
            throw new SignerException(exception);
        }

        // Validando o atributo MessageDigest
        org.bouncycastle.asn1.cms.Attribute attributeMessageDigest = signedAttributesTable.get(CMSAttributes.messageDigest);
        if (attributeMessageDigest == null) {
            throw new SignerException("Package PKCS7 without attribute MessageDigest");
        }
        Object der = attributeMessageDigest.getAttrValues().getObjectAt(0).getDERObject();
        ASN1OctetString octeto = ASN1OctetString.getInstance(der);
        byte[] hashContentSigned = octeto.getOctets();

        String algorithm = SignerAlgorithmEnum.getSignerOIDAlgorithmHashEnum(signerInformation.getDigestAlgorithmID().getObjectId().toString()).getAlgorithmHash();
        if (!algorithm.equals(DigestAlgorithmEnum.SHA_256.getAlgorithm())) {
            throw new SignerException("Algoritmo de resumo inválido para esta política");
        }
        Digest digest = DigestFactory.getInstance().factoryDefault();
        digest.setAlgorithm(DigestAlgorithmEnum.SHA_256.getAlgorithm());
        byte[] hashContent = digest.digest(content);
        if (!MessageDigest.isEqual(hashContentSigned, hashContent)) {
            throw new SignerException("Hash not equal");
        }

        try {
            signerInformation.verify(publicKey, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException(e);
        } catch (NoSuchProviderException e) {
            throw new SignerException(e);
        } catch (CMSException e) {
            throw new SignerException("Invalid signature", e);
        }

        // O atributo signingCertificate deve conter referência apenas ao
        // certificado do signatário.
        org.bouncycastle.asn1.cms.Attribute signedSigningCertificate = signedAttributesTable.get(new DERObjectIdentifier("1.2.840.113549.1.9.16.2.12"));
        if (signedSigningCertificate != null) {
            // Uso futuro, para processamento dos valores
            ASN1Set set = signedSigningCertificate.getAttrValues();
        } else {
            throw new SignerException("O Atributo signingCertificate não pode ser nulo.");
        }

        // Valida a cadeia de certificação de um arquivo assinado
        //ValidadorUtil.validate(contentSigned, OIDICPBrasil.POLICY_ID_AD_RB_CMS_V_2_0, CertPathEncoding.PKCS7);
        
        Date dataSigner = null;
        try {
            org.bouncycastle.asn1.cms.Attribute attributeSigningTime = signedAttributesTable.get(CMSAttributes.signingTime);
            ASN1Set valorDateSigner = attributeSigningTime.getAttrValues();
            DERSet derSet = (DERSet) valorDateSigner.getDERObject();
            DERUTCTime time = (DERUTCTime) derSet.getObjectAt(0);
            dataSigner = time.getAdjustedDate();
        } catch (ParseException ex) {

        }

        //Para a versão 2.0, o período para assinatura desta PA é de 26/12/2011 a 21/06/2023.
        Calendar calendar = GregorianCalendar.getInstance();
        calendar.set(2011, Calendar.DECEMBER, 26, 0, 0, 0);
        Date firstDate = calendar.getTime();

        calendar.set(2023, Calendar.JUNE, 21, 23, 59, 59);
        Date lastDate = calendar.getTime();

        if (dataSigner != null) {
            if (dataSigner.before(firstDate)) {
                throw new SignerException("Invalid signing time. Not valid before 12/26/2011");
            }
            if (dataSigner.after(lastDate)) {
                throw new SignerException("Invalid signing time. Not valid after 06/21/2023");
            }
        } else {
            throw new SignerException("There is SigningTime attribute on Package PKCS7, but it is null");
        }

    }

    /**
     * Efetua a validação da politica para um determinado certificado no momento
     * da assinatura
     *
     * @param certificate
     * @param privateKey
     */
    @Override
    public void validate(X509Certificate certificate, PrivateKey privateKey) {
        /*
         * O tamanho mínimo de chaves para criação de assinaturas segundo esta
         * PA é de :
         *
         * a) para a versão 1.0: 1024 bits; b) para a versão 1.1: 1024 bits; c)
         * para a versão 2.0: 2048 bits.
         */

        if (((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength() < keySize) {
            throw new SignerException("O tamanho mínimo da chave privada deve ser de " + keySize + " bits");
        }

        /*
         * Assinaturas digitais geradas segundo esta Política de Assinatura
         * ICP-Brasil * tipo A1 (do OID 2.16.76.1.2.1.1 ao OID
         * 2.16.76.1.2.1.100), tipo A2 (do OID 2.16.76.1.2.2.1 ao OID
         * 2.16.76.1.2.2.100), do tipo A3 (do OID 2.16.76.1.2.3.1 ao OID
         * 2.16.76.1.2.3.100) e do tipo A4 (do OID 2.16.76.1.2.4.1 ao OID
         * 2.16.76.1.2.4.100), conforme definido em DOC-ICP-04.
         */
        ValidadorUtil.validate(certificate);

        // TODO Implementar a validação do caminho de certificação para o
        // certificado digital a ser utilizado na assinatura
    }

    @Override
    public SignerAlgorithmEnum getSignerAlgorithm() {
        return SignerAlgorithmEnum.SHA256withRSA;
    }

    @Override
    public SigningCertificate getSigningCertificateAttribute(X509Certificate certificate) {
        return new SigningCertificate(certificate);
    }

}
