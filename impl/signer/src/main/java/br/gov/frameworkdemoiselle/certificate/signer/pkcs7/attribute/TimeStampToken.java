/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute;

import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.SignaturePolicy;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimeStampToken implements UnsignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(TimeStampToken.class);
    private PrivateKey privateKey = null;
    private Certificate[] certificates = null;

    @Override
    public String getOID() {
        return "1.2.840.113549.1.9.16.2.14";
    }

    @Override
    public Attribute getValue() {
        //TODO Implementar obtencao do timestamp
        return new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14"), new DERSet());
    }

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {
        this.privateKey = privateKey;
        this.certificates = certificates;
    }

}
