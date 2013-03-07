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

package br.gov.frameworkdemoiselle.security.keystore.loader.implementation;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import javax.security.auth.callback.CallbackHandler;

import se.assembla.jce.provider.ms.MSProvider;
import br.gov.frameworkdemoiselle.security.keystore.loader.KeyStoreLoader;
import br.gov.frameworkdemoiselle.security.keystore.loader.KeyStoreLoaderException;

/**
 * Implementação de KeyStoreLoader baseado no Provider específico do Windows
 * através da biblioteca Assembla. Compatível com JVM 1.5 e anteriores.
 */
public class AssemblaKeyStoreLoader implements KeyStoreLoader {

	protected static final String MSPROVIDER_CLASS = "se.assembla.jce.provider.ms.MSProvider";
	protected static final String MSPROVIDER_ERROR_LOOKUP = "Error on create object from class " + MSPROVIDER_CLASS;
	protected static final String MSPROVIDER_ERROR_LOAD = "Error on load class " + MSPROVIDER_CLASS;

	protected static final String MSPROVIDER_TYPE = "msks";
	protected static final String MSPROVIDER_PROVIDER = "assembla";

	@Override
	public KeyStore getKeyStore() {

		System.out.println("AssemblaKeyStoreLoader.getKeyStore()");

		Provider microsoft = new MSProvider();

		Security.addProvider(microsoft);
		KeyStore keyStore = null;

		try {
			keyStore = KeyStore.getInstance(MSPROVIDER_TYPE, MSPROVIDER_PROVIDER);
			keyStore.load(null, null);
		} catch (Throwable error) {
			throw new KeyStoreLoaderException(MSPROVIDER_ERROR_LOAD, error);
		}

		return keyStore;
	}

	@Override
	public void setCallbackHandler(CallbackHandler callback) {

	}

}
