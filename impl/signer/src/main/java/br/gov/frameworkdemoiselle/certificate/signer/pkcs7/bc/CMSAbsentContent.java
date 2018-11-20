package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
/**
 * @deprecated replaced by Demoiselle SIGNER
 * @see <a href="https://github.com/demoiselle/signer">https://github.com/demoiselle/signer</a>
 * 
 */
@Deprecated
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