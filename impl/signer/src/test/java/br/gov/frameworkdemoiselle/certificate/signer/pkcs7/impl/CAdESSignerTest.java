/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.impl;

import br.gov.frameworkdemoiselle.certificate.signer.factory.PKCS7Factory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.policy.engine.factory.PolicyFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class CAdESSignerTest {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CAdESSignerTest.class);

    @Test
    public void testSignAndVerifySignature() {
        try {
            String configName = "/home/07721825741/drivers.config";
            String password = "";

            Provider p = new sun.security.pkcs11.SunPKCS11(configName);
            Security.addProvider(p);

            KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-Provedor");
            ks.load(null, password.toCharArray());

            Certificate[] certificates = null;

            String alias = "";

            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                alias = e.nextElement();
                logger.info("alias..............: {}", alias);
                certificates = ks.getCertificateChain(alias);
            }

            X509Certificate c = (X509Certificate) certificates[0];
            logger.info("Número de série....: {}", c.getSerialNumber().toString());

            byte[] content = "Hello World".getBytes();

            /* Parametrizando o objeto doSign */
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
            signer.setCertificates(ks.getCertificateChain(alias));
            signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
            signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_1);
            signer.setAttached(true);

            /* Realiza a assinatura do conteudo */
            logger.info("Efetuando a  assinatura do conteudo");
            byte[] signed = signer.doSign(content);

            /* Valida o conteudo */
            logger.info("Efetuando a validacao da assinatura.");
            boolean checked = signer.check(content, signed);

            if (checked) {
                logger.info("A assinatura foi validada.");
            } else {
                logger.info("A assinatura foi invalidada!");
            }

        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex) {
            Logger.getLogger(CAdESSignerTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
