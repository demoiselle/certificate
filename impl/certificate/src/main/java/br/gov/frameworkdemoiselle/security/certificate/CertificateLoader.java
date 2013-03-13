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

package br.gov.frameworkdemoiselle.security.certificate;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Carregamento de Certificados Digitais.
 */
public interface CertificateLoader {

	/**
	 * Obtem o certificado A1 a partir de um arquivo
	 * 
	 * @param file
	 * @return
	 * @throws CertificateException
	 */
	public X509Certificate load(File file) throws CertificateException;

	/**
	 * Obtem o certificado A3 a partir de um dispositivo.
	 * 
	 * @return
	 * @throws CertificateException
	 */
	public X509Certificate loadFromToken() throws CertificateException;

	/**
	 * Obtem o certificado A3 a partir de um dispositivo.
	 * 
	 * @param pinNumber
	 * @return
	 * @throws CertificateException
	 */
	public X509Certificate loadFromToken(String pinNumber) throws CertificateException;

	/**
	 * Obtem o certificado A3 a partir de um dispositivo e de seu alias.
	 * 
	 * @param pinNumber
	 * @param alias
	 *            Alias do certificado
	 * @return
	 * @throws CertificateException
	 */
	public X509Certificate loadFromToken(String pinNumber, String alias) throws CertificateException;

	/**
	 * Seta um KeyStore, evitando criar um.
	 * 
	 * @param keyStore
	 * @throws CertificateException
	 */
	public void setKeyStore(KeyStore keyStore) throws CertificateException;

	/**
	 * Retorna o KeyStore utilizado pelo {@link CertificateLoader}.
	 * 
	 * @return keyStore
	 * @throws CertificateException
	 */
	public KeyStore getKeyStore() throws CertificateException;

}
