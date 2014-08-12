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

import br.gov.frameworkdemoiselle.certificate.IValidator;
import br.gov.frameworkdemoiselle.certificate.ca.manager.CAManager;
import br.gov.frameworkdemoiselle.certificate.signer.SignerAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS1Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs1.PKCS1Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignedAttribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignedOrUnsignedAttribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.UnsignedAttribute;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.factory.AttributeFactory;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.AlgAndLength;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.CertificateTrustPoint;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.ObjectIdentifier;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.SignaturePolicy;
import br.gov.frameworkdemoiselle.policy.engine.factory.PolicyFactory;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CAdESSigner implements PKCS7Signer {

    private static final Logger logger = LoggerFactory.getLogger(CAdESSigner.class);
    private final PKCS1Signer pkcs1 = PKCS1Factory.getInstance().factoryDefault();
    private X509Certificate certificate;
    private Certificate certificateChain[];
    private boolean attached = false;
    private SignaturePolicy signaturePolicy = null;
    private Map<Class<? extends SignedOrUnsignedAttribute>, Collection<SignedOrUnsignedAttribute>> attributes;
    private Collection<IValidator> certificateValidators = null;
    private boolean defaultCertificateValidators = true;

    public CAdESSigner() {
        this.pkcs1.setAlgorithm((String) null);
//        this.setSignaturePolicy(new ADRBCMS_1_0());
    }

    @Override
    public void addAttribute(SignedOrUnsignedAttribute attribute) {
        if (this.attributes == null) {
            this.attributes = new HashMap<>();
        }
        if (attribute != null) {
            Class<? extends SignedOrUnsignedAttribute> clazz = getTypeAttribute(attribute);
            Collection<SignedOrUnsignedAttribute> collection = this.attributes.get(clazz);
            if (collection == null) {
                collection = new HashSet<>();
            }
            collection.add(attribute);
            this.attributes.put(clazz, collection);
        }
    }

    @Override
    public void addAttributes(Collection<SignedOrUnsignedAttribute> attributes) {
        for (SignedOrUnsignedAttribute attribute : attributes) {
            this.addAttribute(attribute);
        }
    }

    public void addCertificateValidator(IValidator validator) {
        if (this.certificateValidators == null) {
            this.certificateValidators = new ArrayList<>();
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
     * @params content Necessário informar apenas se o pacote PKCS7 NÃO for do
     * tipo ATTACHED. Caso seja do tipo attached, este parâmetro será
     * substituido pelo conteúdo do pacote PKCS7.
     * @params signed Valor em bytes do pacote PKCS7, como por exemplo o
     * conteúdo de um arquivo ".p7s". Não é a assinatura pura como no caso do
     * PKCS1. TODO: Implementar validação de co-assinaturas
     */
    @Override
    public boolean check(byte[] content, byte[] signed) {
        Security.addProvider(new BouncyCastleProvider());
        CMSSignedData cmsSignedData = null;
        try {
            if (content == null) {
                cmsSignedData = new CMSSignedData(signed);
            } else {
                cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(content), signed);
            }
        } catch (CMSException ex) {
            throw new SignerException("Bytes inválidos localizados no pacote PKCS7.", ex);
        }

        //Quantidade inicial de assinaturas validadas
        int verified = 0;

        Store certStore = cmsSignedData.getCertificates();
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Iterator<?> it = signers.getSigners().iterator();

        //Realização da verificação básica de todas as assinaturas
        while (it.hasNext()) {
            try {
                SignerInformation signer = (SignerInformation) it.next();
                Collection<?> certCollection = certStore.getMatches(signer.getSID());

                Iterator<?> certIt = certCollection.iterator();
                X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();

                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificateHolder))) {
                    verified++;
                    logger.info("Validada a assinatura digital de sequencia [{}]", verified);
                }

                //Realiza a verificação dos atributos assinados
                logger.info("Efetuando a verificação dos atributos assinados");
                AttributeTable signedAttributes = signer.getSignedAttributes();
                if (signedAttributes.size() == 0) {
                    throw new SignerException("O pacote PKCS7 não contém atributos assinados.");
                }

                AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
                if (unsignedAttributes.size() == 0) {
                    logger.info("O pacote PKCS7 não contem atributos nao assinados.");
                }

                //Mostra a hora da assinatura
                logger.info("yyMMddHHmmssz : {}", (((ASN1UTCTime) signedAttributes.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.5")).getAttrValues().getObjectAt(0)).getTime()));

                // Valida a política de assinatura
//                org.bouncycastle.asn1.cms.Attribute signaturePolicyIdentifierAttribute = signedAttributes.get(new ASN1ObjectIdentifier((new SignaturePolicyIdentifier()).getOID()));
//                if (signaturePolicyIdentifierAttribute != null) {
//                    ASN1Set valueAttribute = signaturePolicyIdentifierAttribute.getAttrValues();
//                    for (Enumeration<DERSequence> iterator = valueAttribute.getObjects(); iterator.hasMoreElements();) {
//                        DERSequence sequence = iterator.nextElement();
//                        ASN1ObjectIdentifier policyIdentifier = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
//                        String policyOID = policyIdentifier.getId();
//                        SignaturePolicy signaturePolicy = SignaturePolicyFactory.getInstance().factory(policyOID);
//                        if (signaturePolicy != null) {
//                            signaturePolicy.validate(content, signed);
//                        } else {
//                            logger.warn("Não existe validador para a política " + policyOID);
//                        }
//                    }
//                } else {
//                    throw new SignerException("Formato ICP-Brasil inválido. Não existe uma política de assinatura.");
//                }
            } catch (OperatorCreationException | java.security.cert.CertificateException ex) {
                throw new SignerException(ex);
            } catch (CMSException ex) {
                throw new SignerException("A assinatura fornecida é inválida.", ex);
            }
        }

        logger.info("Verificada(s) {} assinatura(s).", verified);

        return true;
    }

    private Store generatedCertStore() {
        Store result = null;
        try {
            List<Certificate> certificates = new ArrayList<>();
            certificates.addAll(Arrays.asList(certificateChain));
            CollectionCertStoreParameters cert = new CollectionCertStoreParameters(certificates);
            result = new JcaCertStore(certificates);

        } catch (CertificateEncodingException ex) {
            throw new SignerException(ex);
        }
        return result;
    }

    @Override
    public String getAlgorithm() {
        return this.signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue();
    }

    /**
     * Retorna o conteúdo original do arquivo assinado
     *
     * @param signed O conteúdo assinado
     * @return O conteúdo original
     */
    public byte[] getAttached(byte[] signed) {
        return this.getAttached(signed, true);
    }

    /**
     * Extrai o conteudo assinado da estrutura de assinatura digital, caso
     * exista
     *
     * @param signed O conteudo assinado
     * @param validateOnExtract Extrai validando a assinatura, em caso
     * verdadeiro.
     * @return O conteudo original
     */
    @Override
    public byte[] getAttached(byte[] signed, boolean validateOnExtract) {

        byte[] result = null;

        if (validateOnExtract) {
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
    public Collection<SignedOrUnsignedAttribute> getAttributes() {
        Collection<SignedOrUnsignedAttribute> result = new ArrayList<>();
        Set<Class<? extends SignedOrUnsignedAttribute>> keys = this.attributes.keySet();
        for (Class<? extends SignedOrUnsignedAttribute> key : keys) {
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

    private Class<? extends SignedOrUnsignedAttribute> getTypeAttribute(SignedOrUnsignedAttribute attribute) {
        if (attribute instanceof UnsignedAttribute) {
            return UnsignedAttribute.class;
        } else if (attribute instanceof SignedAttribute) {
            return SignedAttribute.class;
        }
        throw new SignerException("O atributo é inválido. Ele dever ser do tipo \"SignedAttribute\" ou \"UnsignedAttribute\"");
    }

    public boolean isDefaultCertificateValidators() {
        return this.defaultCertificateValidators;
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

    /**
     * Método de assinatura de dados e geração do pacote PKCS7 Assina apenas com
     * o conteúdo do tipo DATA: OID ContentType 1.2.840.113549.1.9.3 = OID Data
     * 1.2.840.113549.1.7.1 Utiliza o algoritmo da propriedade algorithm. Caso
     * essa propriedade não seja informada, o algoritmo do enum
     * {@link SignerAlgorithmEnum.DEFAULT} será usado. Para este método é
     * necessário informar o conteúdo, a chave privada e um certificado digital
     * padrão ICP-Brasil.
     *
     * @param content Conteúdo a ser assinado. TODO: Implementar co-assinaturas,
     * informar a política de assinatura
     */
    @Override
    public byte[] doSign(byte[] content) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            //Completa os certificados ausentes da cadeia, se houver
            if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
                this.certificate = (X509Certificate) this.certificateChain[0];
            }

            if (this.certificateChain == null || this.certificateChain.length <= 1) {
                this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);
            }

            AttributeFactory attributeFactory = AttributeFactory.getInstance();

            //Consulta e adiciona os atributos assinados
            ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

            if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers() != null) {
                for (ObjectIdentifier oi : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers()) {

                    SignedOrUnsignedAttribute sua = attributeFactory.factory(oi.getValue());
                    sua.initialize(this.pkcs1.getPrivateKey(), certificateChain, content, signaturePolicy);
                    signedAttributes.add(sua.getValue());
                }
            }

            //Consulta e adiciona os atributos não assinados
            ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();

            if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
                for (ObjectIdentifier oi : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {

                    SignedOrUnsignedAttribute sua = attributeFactory.factory(oi.getValue());
                    sua.initialize(this.pkcs1.getPrivateKey(), certificateChain, content, signaturePolicy);
                    logger.info(attributeFactory.factory(oi.getValue()).getClass().getName());
                }
            }

            //Monta a tabela de atributos assinados e não assinados
            AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            AttributeTable unsignedAttributesTable = new AttributeTable(unsignedAttributes);

            // Create the table table generator that will added to the Signer builder
            CMSAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);
            CMSAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributesTable);

            //Recupera o algoritmo e o tamanho minimo da chave
            AlgAndLength algAndLength = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getAlgorithmConstraintSet().getSignerAlgorithmConstraints().getAlgAndLengths().iterator().next();

            logger.info("AlgID........... {}", algAndLength.getAlgID().getValue());
            logger.info("Alg Name........ {}", AlgorithmNames.getAlgorithmName(algAndLength.getAlgID().getValue()));
            logger.info("MinKeyLength.... {}", algAndLength.getMinKeyLength());

            //Recupera o(s) certificado(s) de confianca
            Collection<CertificateTrustPoint> ctp = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSigningCertTrustCondition().getSignerTrustTrees().getCertificateTrustPoints();
            for (CertificateTrustPoint certificateTrustPoint : ctp) {
                logger.info(certificateTrustPoint.getTrustpoint().getSubjectDN().toString());
            }

            //Recupera a data de validade da politica para validacao
            Date dateNotBefore = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod().getNotBefore().getDate();
            Date dateNotAfter = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod().getNotAfter().getDate();

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addCertificates(this.generatedCertStore());

            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder().setSignedAttributeGenerator(signedAttributeGenerator).setUnsignedAttributeGenerator(unsignedAttributeGenerator).build(AlgorithmNames.getAlgorithmName(algAndLength.getAlgID().getValue()), this.pkcs1.getPrivateKey(), this.certificate);
            gen.addSignerInfoGenerator(signerInfoGenerator);

            CMSTypedData cmsTypedData;
            if (content == null) {
                //TODO Verificar a necessidade da classe CMSAbsentContent local
                cmsTypedData = new CMSAbsentContent();
            } else {
                cmsTypedData = new CMSProcessableByteArray(content);
            }

            //TODO Estudar este método de contra-assinatura posteriormente
            //gen.generateCounterSigners(null);
            //Efetua a assinatura digital do conteúdo
            CMSSignedData cmsSignedData = gen.generate(cmsTypedData, this.attached);
            byte[] result = cmsSignedData.getEncoded();
            return result;

        } catch (CMSException | IOException | OperatorCreationException ex) {
            throw new SignerException(ex);
        } catch (CertificateEncodingException ex) {
            logger.info(ex.getMessage());
        }
        return null;
    }

    @Override
    public void setSignaturePolicy(PolicyFactory.Policies signaturePolicy) {
        PolicyFactory policyFactory = PolicyFactory.getInstance();
        br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.SignaturePolicy sp = policyFactory.loadPolicy(signaturePolicy);
        this.signaturePolicy = sp;
    }

    private enum AlgorithmNames {

        sha1WithRSAEncryption("1.2.840.113549.1.1.5", "SHA1withRSA"),
        sha256WithRSAEncryption("1.2.840.113549.1.1.11", "SHA256withRSA");

        private final String oid;
        private final String algorithmName;

        private AlgorithmNames(String oid, String name) {
            this.oid = oid;
            this.algorithmName = name;
        }

        public static String getAlgorithmName(String oid) {

            switch (oid) {
                case "1.2.840.113549.1.1.5": {
                    return sha1WithRSAEncryption.algorithmName;
                }
                case "1.2.840.113549.1.1.11": {
                    return sha256WithRSAEncryption.algorithmName;
                }
                default: {
                    return sha1WithRSAEncryption.algorithmName;
                }
            }
        }
    }
}
