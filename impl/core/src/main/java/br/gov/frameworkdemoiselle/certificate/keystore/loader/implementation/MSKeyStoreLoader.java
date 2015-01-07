/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package br.gov.frameworkdemoiselle.certificate.keystore.loader.implementation;

import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoader;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoaderException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.security.auth.callback.CallbackHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementação de KeyStoreLoader baseado no Provider específico do Windows que
 * acompanha a distribuição da Sun JVM 1.6.
 */
public class MSKeyStoreLoader implements KeyStoreLoader {

    private static final Logger logger = LoggerFactory.getLogger(MSKeyStoreLoader.class);
    protected static final String MS_PROVIDER = "SunMSCAPI";
    protected static final String MS_TYPE = "Windows-MY";
    protected static final String MS_ERROR_LOAD = "Error on load a KeyStore from SunMSCAPI";
    private static CallbackHandler callback;

    @Override
    public KeyStore getKeyStore() {
        try {
            KeyStore result = KeyStore.getInstance(MSKeyStoreLoader.MS_TYPE, MSKeyStoreLoader.MS_PROVIDER);
            result.load(null, null);
            fixAliases(result);
            return result;
        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            throw new KeyStoreLoaderException(MSKeyStoreLoader.MS_ERROR_LOAD, ex);
        }
    }

    @Override
    public void setCallbackHandler(CallbackHandler callback) {
        MSKeyStoreLoader.setCallback(callback);
    }

    /**
     * Implementacao do metodo de contorno para evitar a duplicidade de
     * certificados, conforme descrito em
     * <http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6672015>
     *
     * @param keyStore
     */
    private void fixAliases(KeyStore keyStore) {
        Field field;
        KeyStoreSpi keyStoreVeritable;

        try {
            field = keyStore.getClass().getDeclaredField("keyStoreSpi");
            field.setAccessible(true);
            keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

            if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
                Collection<?> entries;
                String alias, hashCode;
                X509Certificate[] certificates;

                field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
                field.setAccessible(true);
                entries = (Collection<?>) field.get(keyStoreVeritable);

                for (Object entry : entries) {
                    field = entry.getClass().getDeclaredField("certChain");
                    field.setAccessible(true);
                    certificates = (X509Certificate[]) field.get(entry);

                    hashCode = Integer.toString(certificates[0].hashCode());

                    field = entry.getClass().getDeclaredField("alias");
                    field.setAccessible(true);
                    alias = (String) field.get(entry);

                    if (!alias.equals(hashCode)) {
                        field.set(entry, alias.concat(" - ").concat(hashCode));
                    }
                }
            }
        } catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException ex) {
            logger.info(ex.getMessage());
            ex.printStackTrace();
        }
    }

	public static CallbackHandler getCallback() {
		return callback;
	}

	public static void setCallback(CallbackHandler callback) {
		MSKeyStoreLoader.callback = callback;
	}
}
