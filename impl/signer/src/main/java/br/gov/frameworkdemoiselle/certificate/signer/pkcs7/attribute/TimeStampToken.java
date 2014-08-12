/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute;

import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.SignaturePolicy;
import br.gov.frameworkdemoiselle.timestamp.TimestampGenerator;
import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import br.gov.frameworkdemoiselle.timestamp.exception.TimestampException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimeStampToken implements UnsignedAttribute {

    private static final Logger logger = LoggerFactory.getLogger(TimeStampToken.class);
    private final String identifier = "1.2.840.113549.1.9.16.2.14";
    private PrivateKey privateKey = null;
    private Certificate[] certificates = null;
    byte[] content = null;

    @Override
    public String getOID() {
        return identifier;
    }

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {
        this.privateKey = privateKey;
        this.certificates = certificates;
        this.content = content;
    }

    @Override
    public Attribute getValue() throws SignerException {
        try {
            TimestampGenerator timestampGen = new TimestampGenerator();
            byte[] request = timestampGen.createRequest(content, privateKey, certificates, DigestAlgorithmEnum.SHA_256);
            byte[] response = timestampGen.doTimestamp(request, ConnectionType.SOCKET);
            timestampGen.validate(response, content);
            logger.info(timestampGen.getTimestamp().toString());

            return new Attribute(new ASN1ObjectIdentifier(identifier), new DERSet());
        } catch (TimestampException | IOException ex) {
            throw new SignerException(ex.getMessage());
        }
    }
}
