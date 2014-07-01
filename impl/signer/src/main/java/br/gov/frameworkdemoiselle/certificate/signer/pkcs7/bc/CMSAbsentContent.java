package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

public class CMSAbsentContent implements CMSTypedData {

    @Override
    public ASN1ObjectIdentifier getContentType() {
        return null;
    }

    @Override
    public void write(OutputStream out) throws IOException, CMSException {

    }

    @Override
    public Object getContent() {
        return null;
    }

}
