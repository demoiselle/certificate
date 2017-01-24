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
package br.gov.frameworkdemoiselle.certificate.ca.provider.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownServiceException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import br.gov.frameworkdemoiselle.certificate.ca.provider.ProviderCA;

public class ICPBrasilOnLineProviderCA implements ProviderCA {

	private static final String STRING_URL = "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";
	private static final int TIMEOUT = 5000;

	public String getURL() {
		return ICPBrasilOnLineProviderCA.STRING_URL;
	}

	@Override
	public Collection<X509Certificate> getCAs() {
		
		// TODO: Cache
		
		System.out.println("Recuperando remotamente as cadeias da ICP-Brasil através do link [" + getURL() + "].");
		System.out.print("Iniciando a recuperação ... ");
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		long timeBefore = 0;
		long timeAfter = 0;
		try {
			timeBefore = System.currentTimeMillis();
			result = this.getFromZip(this.getInputStreamFromURL(STRING_URL));
			timeAfter = System.currentTimeMillis();
			System.out.print("OK. ");
		} catch (Throwable error) {
			timeAfter = System.currentTimeMillis();
			System.out.print(" ERRO. [" + error.getMessage() + "]. ");
		} finally {
			System.out.println("Levamos " + (timeAfter - timeBefore) + "ms para recuperar as cadeias.");
		}
		return result;
	}

	public Collection<X509Certificate> getFromZip(InputStream zip) throws RuntimeException {
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		InputStream in = new BufferedInputStream(zip);
		ZipInputStream zin = new ZipInputStream(in);
		ZipEntry arquivoInterno = null;
		try {
			while ((arquivoInterno = zin.getNextEntry()) != null) {
				if (!arquivoInterno.isDirectory()) {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					byte[] b = new byte[512];
					int len = 0;
					while ((len = zin.read(b)) != -1)
						out.write(b, 0, len);
					ByteArrayInputStream is = new ByteArrayInputStream(out.toByteArray());
					out.close();
					X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509")
							.generateCertificate(is);
					is.close();
					result.add(certificate);
				}
			}
		} catch (CertificateException error) {
			throw new RuntimeException("Certificado inválido", error);
		} catch (IOException error) {
			throw new RuntimeException("Erro ao tentar abrir o stream", error);
		}
		return result;
	}

	public InputStream getInputStreamFromURL(String stringURL) throws RuntimeException {
		try {
			URL url = new URL(stringURL);
			URLConnection connection = url.openConnection();
			connection.setConnectTimeout(TIMEOUT);
			connection.setReadTimeout(TIMEOUT);
			return connection.getInputStream();
		} catch (MalformedURLException error) {
			throw new RuntimeException("URL mal formada", error);
		} catch (UnknownServiceException error) {
			throw new RuntimeException("Serviço da URL desconhecido", error);
		} catch (IOException error) {
			throw new RuntimeException("Algum erro de I/O ocorreu", error);
		}
	}

	@Override
	public String getName() {
		return "ICP Brasil ONLINE Provider (" + getURL() + ")";
	}

}