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
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc;

import br.gov.frameworkdemoiselle.certificate.CertificateException;
import br.gov.frameworkdemoiselle.certificate.CertificateManager;
import br.gov.frameworkdemoiselle.certificate.CertificateValidatorException;
import br.gov.frameworkdemoiselle.certificate.IValidator;
import br.gov.frameworkdemoiselle.certificate.ca.manager.CAManager;
import br.gov.frameworkdemoiselle.certificate.extension.BasicCertificate;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS1Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs1.PKCS1Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.SignaturePolicy;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.SignaturePolicyFactory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.Attribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignaturePolicyIdentifier;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignedAttribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigningCertificate;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.UnsignedAttribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.attribute.BCAdapter;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.attribute.BCAttribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.policies.ADRBCMS_1_0;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Assinatura de dados no formato PKCS#7 Implementalção baseada na RFC5126 -
 * CAdES (http://tools.ietf.org/html/rfc5126) e voltada para uso no âmbito
 * ICP-Brasil.
 */
public class CAdESSigner implements PKCS7Signer {

    private static final Logger log = LoggerFactory.getLogger(CAdESSigner.class);
    private final PKCS1Signer pkcs1 = PKCS1Factory.getInstance().factoryDefault();
    private X509Certificate certificate;
    private Certificate certificateChain[];
    private boolean attached = false;
    private SignaturePolicy signaturePolicy = null;
    private Map<Class<? extends Attribute>, Collection<Attribute>> attributes;
    private Collection<IValidator> certificateValidators = null;
    private boolean defaultCertificateValidators = true;

    public CAdESSigner() {
        this.pkcs1.setAlgorithm((String) null);
        this.setSignaturePolicy(new ADRBCMS_1_0());
    }

    @Override
    public void addAttribute(Attribute attribute) {
        if (this.attributes == null) {
            this.attributes = new HashMap<Class<? extends Attribute>, Collection<Attribute>>();
        }
        if (attribute != null) {
            Class<? extends Attribute> clazz = getTypeAttribute(attribute);
            Collection<Attribute> collection = this.attributes.get(clazz);
            if (collection == null) {
                collection = new HashSet<Attribute>();
            }
            collection.add(attribute);
            this.attributes.put(clazz, collection);
        }
    }

    @Override
    public void addAttributes(Collection<Attribute> attributes) {
        for (Attribute attribute : attributes) {
            this.addAttribute(attribute);
        }
    }

    public void addCertificateValidator(IValidator validator) {
        if (this.certificateValidators == null) {
            this.certificateValidators = new ArrayList<IValidator>();
        }
        if (!this.certificateValidators.contains(validator)) {
            this.certificateValidators.add(validator);
        }
    }

    /**
     * A validação se basea apenas em assinaturas com um assinante apenas.
     * Valida apenas com o conteúdo do tipo DATA: OID ContentType
     * 1.2.840.113549.1.9.3 = OID Data 1.2.840.113549.1.7.1
     *
     * @param content
     * @param signed
     * @return
     * @params content Necessário informar apenas se o pacote PKCS7 NÃO for do
     * tipo ATTACHED. Caso seja do tipo attached, este parâmetro será
     * substituido pelo conteúdo do pacote PKCS7.
     * @params signed Valor em bytes do pacote PKCS7, como por exemplo o
     * conteúdo de um arquivo ".p7s". Não é a assinatura pura como no caso do
     * PKCS1. TODO: Implementar validação de co-assinaturas
     */
    @Override
    public boolean check(byte[] content, byte[] signed) {

        CMSSignedData signedData = null;
        PublicKey publicKey = null;

        try {
            if (content == null) {
                signedData = new CMSSignedData(signed);
            } else {
                signedData = new CMSSignedData(new CMSProcessableByteArray(content), signed);
            }
        } catch (CMSException exception) {
            throw new SignerException("Invalid bytes for a PKCS7 package", exception);
        }

        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        SignerInformation signerInformation = (SignerInformation) signerInformationStore.getSigners().iterator().next();

        /*
         * Retirando o Certificado Digital e a chave Pública da assinatura
         */
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
        } catch (SignerException ex) {
            throw new SignerException("Error on get information about certificates and public keys from a package PKCS7", ex);
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

        AttributeTable signedAttributes = signerInformation.getSignedAttributes();

        if (signedAttributes == null) {
            throw new SignerException("Package PKCS7 without signed attributes");
        }

        // Validar a política
        org.bouncycastle.asn1.cms.Attribute signaturePolicyIdentifierAttribute = signedAttributes
                .get(new DERObjectIdentifier((new SignaturePolicyIdentifier()).getOID()));
        if (signaturePolicyIdentifierAttribute != null) {
            ASN1Set valueAttribute = signaturePolicyIdentifierAttribute.getAttrValues();
            for (Enumeration<DERSequence> iterator = valueAttribute.getObjects(); iterator.hasMoreElements();) {
                DERSequence sequence = iterator.nextElement();
                DERObjectIdentifier policyIdentifier = (DERObjectIdentifier) sequence.getObjectAt(0);
                String policyOID = policyIdentifier.getId();
                SignaturePolicy policy = SignaturePolicyFactory.getInstance().factory(policyOID);
                if (policy != null) {
                    policy.validate(content, signed);
                } else {
                    log.warn("Não existe validador para a política " + policyOID);
                }
            }
        } else {
            throw new SignerException("ICP-Brasil invalid format. There is not policy signature.");
        }
        return true;
    }

    private CertStore generatedCertStore() {
        CertStore result = null;
        try {
            List<Certificate> certificates = new ArrayList<Certificate>();

            // TODO Avaliar se pega todos os certificados
            for (Certificate certChain : certificateChain) {
                certificates.add(certChain);
            }

            CollectionCertStoreParameters cert = new CollectionCertStoreParameters(certificates);
            result = CertStore.getInstance("Collection", cert, "BC");

        } catch (InvalidAlgorithmParameterException exception) {
            throw new SignerException(exception);
        } catch (NoSuchAlgorithmException exception) {
            throw new SignerException(exception);
        } catch (NoSuchProviderException exception) {
            throw new SignerException(exception);
        }
        return result;
    }

    @Override
    public String getAlgorithm() {
        return this.signaturePolicy.getSignerAlgorithm().getAlgorithm();
    }

    public byte[] getAttached(byte[] signed) {

        return this.getAttached(signed, true);

    }

    @Override
    public byte[] getAttached(byte[] signed, boolean validate) {

        byte[] result = null;

        if (validate) {
            this.check(null, signed);
        }

        CMSSignedData signedData = null;
        try {
            signedData = new CMSSignedData(signed);
        } catch (CMSException exception) {
            throw new SignerException("Invalid bytes for a package PKCS7", exception);
        }

        try {
            CMSProcessable contentProcessable = signedData.getSignedContent();
            if (contentProcessable != null) {
                result = (byte[]) contentProcessable.getContent();
            }
        } catch (Exception exception) {
            throw new SignerException("Error on get content from PKCS7", exception);
        }

        return result;

    }

    @Override
    public Collection<Attribute> getAttributes() {
        Collection<Attribute> result = new ArrayList<Attribute>();
        Set<Class<? extends Attribute>> keys = this.attributes.keySet();
        for (Class<? extends Attribute> key : keys) {
            result.addAll(this.attributes.get(key));
        }
        return result;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return this.pkcs1.getPrivateKey();
    }

    @Override
    public Provider getProvider() {
        return this.pkcs1.getProvider();
    }

    private String getProviderName() {
        if (this.pkcs1.getProvider() != null) {
            return this.pkcs1.getProvider().getName();
        }
        return null;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.pkcs1.getPublicKey();
    }

    private Class<? extends Attribute> getTypeAttribute(Attribute attribute) {
        if (attribute instanceof UnsignedAttribute) {
            return UnsignedAttribute.class;
        } else if (attribute instanceof SignedAttribute) {
            return SignedAttribute.class;
        }
        throw new SignerException("Attribute invalid. Attribute should be SignedAttribute or UnsignedAttribute");
    }

    public boolean isDefaultCertificateValidators() {
        return this.defaultCertificateValidators;
    }

    private AttributeTable mountAttributeTable(Collection<Attribute> collection) {
        if (collection == null || collection.isEmpty()) {
            return null;
        }
        AttributeTable table = null;
        Hashtable<DERObjectIdentifier, org.bouncycastle.asn1.cms.Attribute> attributes = new Hashtable<DERObjectIdentifier, org.bouncycastle.asn1.cms.Attribute>();
        for (Attribute attribute : collection) {
            org.bouncycastle.asn1.cms.Attribute bcAttribute = this.transformAttribute(attribute);
            attributes.put(bcAttribute.getAttrType(), bcAttribute);
        }

        if (attributes.size() > 0) {
            table = new AttributeTable(attributes);
        }
        return table;
    }

    private AttributeTable mountSignedTable() {
        if (this.attributes != null && this.attributes.size() > 0) {
            return this.mountAttributeTable(this.attributes.get(SignedAttribute.class));
        }
        return null;
    }

    private AttributeTable mountUnsignedTable() {
        if (this.attributes != null && this.attributes.size() > 0) {
            return this.mountAttributeTable(this.attributes.get(UnsignedAttribute.class));
        }
        return null;
    }

    @Override
    public void setAlgorithm(SignerAlgorithmEnum algorithm) {
        this.pkcs1.setAlgorithm(algorithm);
    }

    @Override
    public void setAlgorithm(String algorithm) {
        this.pkcs1.setAlgorithm(algorithm);
    }

    @Override
    public void setAttached(boolean attached) {
        this.attached = attached;
    }

    @Override
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    @Override
    public void setCertificates(Certificate[] certificates) {
        this.certificateChain = certificates;
    }

    public void setDefaultCertificateValidators(boolean defaultCertificateValidators) {
        this.defaultCertificateValidators = defaultCertificateValidators;
    }

    @Override
    public void setPrivateKey(PrivateKey privateKey) {
        this.pkcs1.setPrivateKey(privateKey);
    }

    @Override
    public void setProvider(Provider provider) {
        this.pkcs1.setProvider(provider);
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        this.pkcs1.setPublicKey(publicKey);
    }

    @Override
    public void setSignaturePolicy(SignaturePolicy signaturePolicy) {
        if (signaturePolicy == null) {
            return;
        }
        this.signaturePolicy = signaturePolicy;
    }

    /**
     * Método de assinatura de dados e geração do pacote PKCS7 Assina apenas com
     * o conteúdo do tipo DATA: OID ContentType 1.2.840.113549.1.9.3 = OID Data
     * 1.2.840.113549.1.7.1 Utiliza o algoritmo da propriedade algorithm. Caso
     * essa propriedade não esteja setada, o algoritmo do enum
     * {@link SignerAlgorithmEnum.DEFAULT} será usado. Para este método é
     * necessário informar o conteúdo, a chave privada e um certificado digital
     * padrão ICP-Brasil.
     *
     * @param content Conteúdo a ser assinado. TODO: Implementar co-assinaturas,
     * informar a política de assinatura
     * @return
     */
    @Override
    public byte[] signer(byte[] content) {
        Security.addProvider(new BouncyCastleProvider());

        if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
            this.certificate = (X509Certificate) this.certificateChain[0];
        }

        this.validateForSigner(content);

        if (this.certificateChain == null || this.certificateChain.length <= 1) {
            this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);
        }

        //Adiciona o atributo de identificacao da politica
        SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier();
        signaturePolicyIdentifier.setSignaturePolicyId(this.signaturePolicy.getSignaturePolicyId());
        this.addAttribute(signaturePolicyIdentifier);

        //Adiciona o astributo certificado de assinatura
        boolean addSigningCertificateAttribute = true;
        for (Attribute attribute : this.getAttributes()) {
            if (attribute instanceof SigningCertificate) {
                addSigningCertificateAttribute = false;
                break;
            }
        }
        if (addSigningCertificateAttribute) {
            SigningCertificate signingCertificateAttribute = this.signaturePolicy.getSigningCertificateAttribute(this.certificate);
            this.addAttribute(signingCertificateAttribute);
        }

        this.setCertificate((X509Certificate) certificateChain[0]);
        if (certificateChain.length == 1) {
            throw new SignerException("Impossivel extrair a cadeia de confianca do certificado");
        }

        String algorithmHashOID = null;
        String algorithmEncryptationOID = null;
        if (this.pkcs1 != null && this.pkcs1.getAlgorithm() != null && this.pkcs1.getAlgorithm().trim().length() > 0) {
            algorithmHashOID = SignerAlgorithmEnum.valueOf(this.pkcs1.getAlgorithm()).getOIDAlgorithmHash();
            algorithmEncryptationOID = SignerAlgorithmEnum.valueOf(this.pkcs1.getAlgorithm()).getOIDAlgorithmCipher();
        } else {
            algorithmHashOID = this.signaturePolicy.getSignerAlgorithm().getOIDAlgorithmHash();
            algorithmEncryptationOID = this.signaturePolicy.getSignerAlgorithm().getOIDAlgorithmCipher();
        }

        byte[] result = null;

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
        try {
            signedDataGenerator.addCertificatesAndCRLs(this.generatedCertStore());
        } catch (CertStoreException e) {
            throw new SignerException(e);
        } catch (CMSException e) {
            throw new SignerException(e);
        }

        // Valida o certificado usando a politica de certificacao
        this.signaturePolicy.validate(this.certificate, this.pkcs1.getPrivateKey());

        AttributeTable signedTable = this.mountSignedTable();
        AttributeTable unsignedTable = this.mountUnsignedTable();
        signedDataGenerator.addSigner(this.pkcs1.getPrivateKey(), this.certificate, algorithmEncryptationOID, algorithmHashOID, signedTable, unsignedTable);

        try {
            CMSProcessable processable = null;
            if (content == null) {
                processable = new CMSAbsentContent();
            } else {
                processable = new CMSProcessableByteArray(content);
            }
            CMSSignedData signedData = signedDataGenerator.generate(CMSSignedDataGenerator.DATA, processable,
                    this.attached, this.getProviderName(), true);
            result = signedData.getEncoded();
        } catch (IOException e) {
            throw new SignerException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException(e);
        } catch (NoSuchProviderException e) {
            throw new SignerException(e);
        } catch (CMSException e) {
            throw new SignerException(e);
        }

        return result;
    }

    private org.bouncycastle.asn1.cms.Attribute transformAttribute(Attribute attribute) {
        BCAttribute adapter = BCAdapter.factoryBCAttribute(attribute);
        return new org.bouncycastle.asn1.cms.Attribute(adapter.getObjectIdentifier(), adapter.getValue());
    }

    private void validateForSigner(byte... content) {
        if (this.pkcs1 == null) {
            throw new SignerException("Please enter the required properties");
        }
        if (this.pkcs1.getPrivateKey() == null) {
            throw new SignerException("Private Key is null");
        }
        if (this.certificate == null) {
            throw new SignerException("Certificate is null");
        } else {
            BasicCertificate basicCertificate = new BasicCertificate(this.certificate);
            try {
                List<String> listLCRs = basicCertificate.getCRLDistributionPoint();
                if (listLCRs == null || listLCRs.isEmpty()) {
                    throw new SignerException("Blank LCR distribuition point for certificate.");
                }
            } catch (IOException error) {
                throw new SignerException("Error on read CRL distribuition point from Certificate");
            }
            try {
                if (this.certificateValidators == null || this.certificateValidators.isEmpty()) {
                    new CertificateManager(this.certificate, this.defaultCertificateValidators);
                } else {
                    new CertificateManager(this.certificate, this.defaultCertificateValidators,
                            this.certificateValidators.toArray(new IValidator[]{}));
                }
            } catch (Throwable exception) {
                if (exception instanceof CertificateException) {
                    throw (CertificateException) exception;
                }
                if (exception instanceof CertificateValidatorException) {
                    throw (CertificateValidatorException) exception;
                }
                throw new SignerException("Certificate is not valid", exception);
            }
        }
    }
}
