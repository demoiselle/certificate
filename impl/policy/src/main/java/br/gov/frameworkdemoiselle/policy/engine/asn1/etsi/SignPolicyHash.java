package br.gov.frameworkdemoiselle.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.DEROctetString;

public class SignPolicyHash extends OctetString {
	public SignPolicyHash(DEROctetString derOctetString) {
		this.derOctetString = derOctetString;
	}
}
