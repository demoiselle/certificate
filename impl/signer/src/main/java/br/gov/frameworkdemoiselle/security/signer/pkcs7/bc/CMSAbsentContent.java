package br.gov.frameworkdemoiselle.security.signer.pkcs7.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;

public class CMSAbsentContent implements CMSProcessable {

	public CMSAbsentContent() {
	}

	@Override
	public void write(OutputStream zOut) throws IOException, CMSException {
	}

	@Override
	public Object getContent() {
		return null;
	}
}