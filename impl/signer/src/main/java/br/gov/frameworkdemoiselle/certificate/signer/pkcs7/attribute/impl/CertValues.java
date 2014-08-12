/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.impl;

import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.UnsignedAttribute;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.SignaturePolicy;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class CertValues implements UnsignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(CertValues.class);
    private String identifier = "1.2.840.113549.1.9.16.2.23";

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {
        logger.info("Not supported yet.");
    }

    @Override
    public String getOID() {
        return identifier;
    }

    @Override
    public Attribute getValue() throws SignerException {
        logger.info("Not supported yet.");
        return new Attribute(new ASN1ObjectIdentifier(identifier), new DERSet());
    }

}
