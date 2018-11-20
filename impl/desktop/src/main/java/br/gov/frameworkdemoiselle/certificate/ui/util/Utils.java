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

package br.gov.frameworkdemoiselle.certificate.ui.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import br.gov.frameworkdemoiselle.certificate.ui.config.FrameConfig;

/**
 * @author SUPST/STDCS
 */
@Deprecated
public final class Utils {

	private static final int BUFFER_SIZE = 4096;

	private static final Logger LOGGER = Logger.getLogger(Utils.class.getName());
	
	/**
	 *
	 * @param content
	 *            O conteudo a ser enviado
	 * @param urlToUpload
	 *            A url para onde o conteudo sera enviado via HTTPS
	 * @param token
	 *            Token que identifica o conteudo a ser enviado	 
	 */
	public static void uploadToURL(byte[] content, String urlToUpload, String token) {
		try {
			ByteArrayInputStream in = new ByteArrayInputStream(content);
			HttpURLConnection con = null;
			if (urlToUpload.startsWith("https")){
				con = getHttpsURLConnection(urlToUpload);
			}else{
				URL url = new URL(urlToUpload);
				con = (HttpURLConnection) url.openConnection();
			}
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/zip");
			con.setRequestProperty("Authorization", "Token " + token);

			OutputStream out = con.getOutputStream();
			copy(in, out);
			out.flush();
			out.close();

			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
				throw new AuthorizationException("Erro de autorização ao acesso o serviço: " + urlToUpload + " com o token " + token);
			}

			if (responseCode != HttpURLConnection.HTTP_NO_CONTENT) {
				Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, "Server returned non-OK code: {0}", responseCode);
				throw new ConectionException("HTTP error code: "+ responseCode);
			}

		} catch (MalformedURLException ex) {
			throw new ConectionException(ex.getMessage(), ex.getCause());
		} catch (IOException ex) {
			throw new ConectionException(ex.getMessage(), ex.getCause());
		}
	}
	
	@Deprecated
	public static void uploadToURL(byte[] content, String urlToUpload, String token, InputStream certificate) {
		Utils.uploadToURL(content, urlToUpload, token);
	}
	
	/**
	 *  @param urlToDownload
	 *            A url para onde o conteudo sera enviado via HTTPS
	 *
	 * @param token
	 *            Token que identifica o conteudo a ser enviado	 
	 * @param certificate
	 *            Certificado para conexão HTTPS, para conexão HTTP setar valor null	 * @return
	 */
	public static byte[] downloadFromUrl(String urlToDownload, String token) {
		ByteArrayOutputStream outputStream = null;
		try {
			outputStream = new ByteArrayOutputStream();
			byte[] chunk = new byte[BUFFER_SIZE];
			int bytesRead;
			HttpURLConnection con = null;
			if (urlToDownload.startsWith("https")){
				con = getHttpsURLConnection(urlToDownload);
			}else{
				URL url = new URL(urlToDownload);
				con = (HttpURLConnection) url.openConnection();
			}
			con.setRequestProperty("Authorization", "Token " + token);
			con.setRequestProperty("Accept", "application/zip");
			con.setRequestMethod("GET");
			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
				throw new AuthorizationException("Erro de autorização ao acesso o serviço: " + urlToDownload + " com o token " + token);
			}
			if (responseCode != HttpURLConnection.HTTP_OK) {
				Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, "Server returned non-OK code: {0}", responseCode);
				throw new ConectionException("HTTP error code: "+ responseCode);
			} else {
				InputStream stream = con.getInputStream();

				while ((bytesRead = stream.read(chunk)) > 0) {
					outputStream.write(chunk, 0, bytesRead);
				}
			}
		} catch (IOException e) {
			throw new ConectionException(e.getMessage(), e.getCause());
		}
		return outputStream.toByteArray();
	}
	
	@Deprecated
	public static byte[] downloadFromUrl(String urlToDownload, String token, InputStream certificate) {
		return Utils.downloadFromUrl(urlToDownload, token);
	}
	
	/**
	 *
	 * @param message
	 *            Mensagem customizada para o serviço
	 * @param urlToCancel
	 *            A url para onde a mensagem sera enviada via HTTPS
	 * @param token
	 *            Token que identifica a mensagem a ser enviada	 
	 * @param certificate
	 *            Certificado para conexão HTTPS, para conexão HTTP setar valor null	                         
	 */
	public static void cancel(String message, String urlToCancel, String token) {
		try {
			InputStream in = new ByteArrayInputStream(message.getBytes());
			
			HttpURLConnection con = null;
			if (urlToCancel.startsWith("https")){
				con = getHttpsURLConnection(urlToCancel);
			}else{
				URL url = new URL(urlToCancel);
				con = (HttpURLConnection) url.openConnection();
			}
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/octet-stream");
			con.setRequestProperty("Authorization", "Token " + token);
			
			OutputStream out = con.getOutputStream();
			copy(in, out);
			out.flush();
			out.close();

			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
				throw new AuthorizationException("Erro de autorização ao acesso o serviço: " + urlToCancel + " com o token " + token);
			}
			if (responseCode != HttpURLConnection.HTTP_NO_CONTENT) {
				Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, "Server returned non-OK code: {0}", responseCode);
				throw new ConectionException("HTTP error code: "+ responseCode);
			}

		} catch (MalformedURLException ex) {
			throw new ConectionException(ex.getMessage(), ex.getCause());
		} catch (IOException ex) {
			throw new ConectionException(ex.getMessage(), ex.getCause());
		}
	}
	
	@Deprecated
	public static void cancel(String message, String urlToCancel, String token, InputStream certificate) {
		Utils.cancel(message, urlToCancel, token);
	}
	
	private static HttpURLConnection getHttpsURLConnection(String urlConnection){
		HttpURLConnection con = null;
		try {
			System.setProperty ("https.protocols", FrameConfig.CONFIG_HTTPS_PROTOCOL.getValue());
	        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
				public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {}
				public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {}
            }};
	        try {
		        SSLContext sc = SSLContext.getInstance(FrameConfig.CONFIG_HTTPS_PROTOCOL.getValue());
		        sc.init(null, trustAllCerts, new java.security.SecureRandom());
		        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	        } catch (Throwable error) {}
	        HostnameVerifier valid = new HostnameVerifier() {
	            public boolean verify(String h, SSLSession s) { return true; }
	        };
	        HttpsURLConnection.setDefaultHostnameVerifier(valid);		
			URL aURL = new URL(urlConnection);
			URLConnection connection = aURL.openConnection();
			con = (HttpsURLConnection)connection;
		} catch (MalformedURLException e) {
			throw new ConectionException(e.getMessage(), e.getCause());
		} catch (IOException e) {
			throw new ConectionException(e.getMessage(), e.getCause());
		}
		return con;
	}

	/**
	 * Read the given binary file, and return its contents as a byte array.
	 *
	 * @param file
	 *            Caminho e nome do arquivo
	 * @return Conteudo lido
	 */
	public static byte[] readContentFromDisk(String file) {
		File f = new File(file);

		byte[] result = new byte[(int) f.length()];
		try {
			InputStream in = null;
			try {
				int totalBytesRead = 0;
				in = new BufferedInputStream(new FileInputStream(f));
				while (totalBytesRead < result.length) {
					int bytesRemaining = result.length - totalBytesRead;
					int bytesRead = in.read(result, totalBytesRead,
							bytesRemaining);
					if (bytesRead > 0) {
						totalBytesRead = totalBytesRead + bytesRead;
					}
				}

			} finally {
				in.close();
			}
		} catch (FileNotFoundException ex) {
			Logger.getLogger(Utils.class.getName()).log(Level.SEVERE,ex.getMessage());
		} catch (IOException ex) {
			Logger.getLogger(Utils.class.getName()).log(Level.SEVERE,ex.getMessage());
		}
		return result;
	}

	/**
	 *
	 * @param content
	 *            Conteudo a ser gravado
	 * @param file
	 *            Caminho e nome do arquivo
	 */
	public static void writeContentToDisk(byte[] content, String file) {
		try {
			File f = new File(file);
			FileOutputStream os = new FileOutputStream(f);
			os.write(content);
			os.flush();
			os.close();
		} catch (IOException ex) {
			Logger.getLogger(Utils.class.getName()).log(Level.SEVERE,ex.getMessage());
		}
	}

	/**
	 *
	 * @param input
	 * @param output
	 * @return
	 * @throws IOException
	 */
	private static long copy(InputStream input, OutputStream output)
			throws IOException {
		byte[] buffer = new byte[BUFFER_SIZE];
		long count = 0L;
		int n = 0;
		while (-1 != (n = input.read(buffer))) {
			output.write(buffer, 0, n);
			count += n;
		}
		return count;
	}
	
	public static byte[] getSSLCertificate(String stringURL) {
		URL url;
		try {
			url = new URL(stringURL);
		} catch (MalformedURLException e) {
			throw new ConectionException(e.getMessage(), e);
		}
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
			public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {}
			public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {}
        }};
        try {
	        SSLContext sc = SSLContext.getInstance(FrameConfig.CONFIG_HTTPS_PROTOCOL.getValue());
	        sc.init(null, trustAllCerts, new java.security.SecureRandom());
	        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Throwable error) {}
        HostnameVerifier valid = new HostnameVerifier() {
            public boolean verify(String h, SSLSession s) { return true; }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(valid);		
		URLConnection connection;
		try {
			connection = url.openConnection();
			connection.connect();
		} catch (IOException e) {
			throw new ConectionException(e.getMessage(), e);
		}
		HttpsURLConnection https = (HttpsURLConnection)connection;
		Certificate[] certificates;
		try {
			certificates = https.getServerCertificates();
		} catch (SSLPeerUnverifiedException e) {
			throw new ConectionException(e.getMessage(), e);
		}
		byte[] result = null;
		try {
			result = certificates[0].getEncoded();
		} catch (CertificateEncodingException e) {
			throw new ConectionException(e.getMessage(), e);
		}
		return result;
	}
	
}
