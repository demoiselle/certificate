package br.gov.frameworkdemoiselle.policy.engine.asn1.etsi;

import br.gov.frameworkdemoiselle.policy.engine.asn1.ASN1Object;
import java.io.UnsupportedEncodingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

public class OctetString extends ASN1Object {

    private String value;
    protected DEROctetString derOctetString;

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getValueUTF8() {
        String result = null;
        try {
            result = new String(this.derOctetString.getOctets(), "UTF8");
        } catch (UnsupportedEncodingException error) {
            throw new RuntimeException("Erro ao tentar converter OctetString em String", error);
        }
        return result;
    }

    public DEROctetString getDerOctetString() {
		return derOctetString;
	}

	public void setDerOctetString(DEROctetString derOctetString) {
		this.derOctetString = derOctetString;
	}

	@Override
    public void parse(ASN1Primitive derObject) {
        if (derObject instanceof DEROctetString) {
            this.derOctetString = (DEROctetString) derObject;
            String octetString = derOctetString.toString();
            octetString = octetString.substring(1);
            this.setValue(octetString);
        }
    }

}
