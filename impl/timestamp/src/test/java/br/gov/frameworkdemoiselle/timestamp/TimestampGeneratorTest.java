/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp;

import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class TimestampGeneratorTest {

    private static final Logger logger = LoggerFactory.getLogger(TimestampGeneratorTest.class);

    byte[] original = null;
    byte[] response = null;

    @Test
    public void testTimeStamp() throws Exception {
        String CLIENT_PASSWORD = "G4bizinh4";

        TimestampGenerator timestampGen = new TimestampGenerator();

        original = "Hello World!".getBytes();

        String token = "name = TokenPro\nlibrary = /usr/lib/libeTPkcs11.so";
        InputStream is = new ByteArrayInputStream(token.getBytes());
        Provider provider = new sun.security.pkcs11.SunPKCS11(is);
        Security.addProvider(provider);

        KeyStore keystore = KeyStore.getInstance("PKCS11", "SunPKCS11-TokenPro");
        keystore.load(is, CLIENT_PASSWORD.toCharArray());
        String alias = keystore.aliases().nextElement();

        PrivateKey pk = (PrivateKey) keystore.getKey(alias, null);

        Certificate[] certificates = keystore.getCertificateChain(alias);

        byte[] pedido = timestampGen.createRequest(original, pk, certificates, DigestAlgorithmEnum.SHA_256);

        byte[] resposta = timestampGen.doTimestamp(pedido, ConnectionType.SOCKET);

        timestampGen.validate(resposta, original);

        logger.info(timestampGen.getTimestamp().toString());
    }

}
