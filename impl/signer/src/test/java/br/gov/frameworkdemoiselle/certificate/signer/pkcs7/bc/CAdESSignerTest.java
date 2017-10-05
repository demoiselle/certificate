package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import javax.net.ssl.KeyManagerFactory;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import br.gov.frameworkdemoiselle.certificate.extension.BasicCertificate;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.implementation.MSKeyStoreLoader;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS7Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.policies.ADRBCMS_2_2;

@SuppressWarnings("unused")
public class CAdESSignerTest {

	@SuppressWarnings({ "restriction"})
	private KeyStore getKeyStoreToken() {

		try {
			// ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO

			// Para TOKEN Branco a linha abaixo
			// String pkcs11LibraryPath =
			// "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";

			// Para TOKEN Azul a linha abaixo
			String pkcs11LibraryPath = "/usr/lib/libeToken.so";

			StringBuilder buf = new StringBuilder();
			buf.append("library = ").append(pkcs11LibraryPath).append("\nname = Provedor\n");
			Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buf.toString().getBytes()));
			Security.addProvider(p);
			// ATENÇÃO ALTERAR "SENHA" ABAIXO
			Builder builder = KeyStore.Builder.newInstance("PKCS11", p,	new KeyStore.PasswordProtection("senha".toCharArray()));
			KeyStore ks;
			ks = builder.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}

	/**
	 * 
	 * Faz a leitura do certificado armazenado em arquivo (A1)
	 */

	private KeyStore getKeyStoreFile() {

		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");

			// Alterar a senha
			char[] senha = "serpro".toCharArray();

			
			// informar onde esta o arquivo
			InputStream ksIs = new FileInputStream("/home/<usuario>/xxxx.p12");
		
			ks.load(ksIs, senha);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, senha);

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}

	}
	
	
	/**
	 * 
	 * Keytore a partir de MSCAPI
	 */
	private KeyStore getKeyStoreOnWindows() {

		try {
			
			MSKeyStoreLoader msKeyStoreLoader = new MSKeyStoreLoader();
			
			KeyStore ks = msKeyStoreLoader.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}

	}
	
	
	
	/**
	 * Teste com envio do conteúdo
	 */
	//@Test
	public void testSignDetached() {
		try {

			System.out.println("******** TESTANDO COM CONTEÚDO *****************");

			// INFORMAR o arquivo
			
			//
			// String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinar.txt";
						
			// String fileDirName = "/home/{usuario}/arquivo_assinar.txt";
			
			String fileDirName = "/home/80621732915/AAssinar/domingos/teste_assinatura_hom.txt";
			

			byte[] fileToSign = readContent(fileDirName);

			// quando certificado em arquivo, precisa informar a senha
			char[] senha = "serpro".toCharArray();

			// Para certificado em Token
			//KeyStore ks = getKeyStoreToken();

			// Para certificado em arquivo A1
			KeyStore ks = getKeyStoreFile();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();
			
			String alias = getAlias(ks);
			/* Parametrizando o objeto doSign */
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(ks.getCertificateChain(alias));

			// para token
			//signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			 signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));

			signer.setSignaturePolicy(new ADRBCMS_2_2());

			// para mudar o algoritimo
			// signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);

			/* Realiza a assinatura do conteudo */
			System.out.println("Efetuando a  assinatura do conteudo");
			// Assinatura desatachada
			byte[] signature = signer.signer(fileToSign);

			/* Valida o conteudo antes de gravar em arquivo */
			System.out.println("Efetuando a validacao da assinatura.");
			Boolean valid = signer.check(fileToSign, signature);

			if (valid) {
				System.out.println("A assinatura foi validada.");
				assertTrue(true);
			} else {
				System.out.println("A assinatura foi invalidada!");
				assertTrue(false);
			}
			File file = new File(fileDirName + ".p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signature);
			os.flush();
			os.close();
			

		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}
	
	//@Test
	public void testVerifyDetachedSignature() {
		String fileToVerifyDirName = "local_e_nome_do_arquivo_assinado";
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura";		
		
		byte[] fileToVerify = readContent(fileToVerifyDirName);
		byte[] signatureFile = readContent(fileSignatureDirName);
		
		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();

		System.out.println("Efetuando a validacao da assinatura");
		assertTrue(signer.check(fileToVerify, signatureFile));	
		
	}
	@Test
	public void certFromDetachedSignature(){
		
		
		
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura";
		
		
		byte[] signatureFile = readContent(fileSignatureDirName);
		X509Certificate certificate;
		CertStore certs;
		BasicCertificate basicCertificate;
		try {
			CMSSignedData signedData = new CMSSignedData(signatureFile);		
			SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        	SignerInformation signerInformation = (SignerInformation) signerInformationStore.getSigners().iterator().next();		
            Security.addProvider(new BouncyCastleProvider());
            certs = signedData.getCertificatesAndCRLs("Collection", "BC");
            Collection<? extends Certificate> collCertificados = certs.getCertificates(signerInformation.getSID());
            if (!collCertificados.isEmpty()) {
            	certificate = (X509Certificate) collCertificados.iterator().next();
            	basicCertificate = new BasicCertificate(certificate);
            	System.out.println(basicCertificate.getICPBRCertificatePF().getCPF());
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
	}
	
	private byte[] readContent(String parmFile) {
		byte[] result = null;
		try {
			File file = new File(parmFile);
			FileInputStream is = new FileInputStream(parmFile);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}

	private String getAlias(KeyStore ks) {
		Certificate[] certificates = null;
		String alias = "";
		Enumeration<String> e;
		try {
			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				System.out.println("alias..............: {}" + alias);
				certificates = ks.getCertificateChain(alias);
			}

		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		}
		X509Certificate c = (X509Certificate) certificates[0];
		System.out.println("Número de série....: {}" + c.getSerialNumber().toString());
		return alias;
	}

}
