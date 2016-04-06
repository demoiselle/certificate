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
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openssl.PEMWriter;

/**
 * @author SUPST/STDCS
*/
public final class Utils {

    private static final int BUFFER_SIZE = 4096;

    /**
     *
     * @param content O conteudo a ser enviado
     * @param UrlToUpload A url para onde o conteudo sera enviado
     */
    public static void uploadToURL(byte[] content, String UrlToUpload, String token) {
        try {
            System.out.println("br.gov.serpro.certificate.ui.util.Utils.uploadToURL()");

            ByteArrayInputStream in = new ByteArrayInputStream(content);
            URL url = new URL(UrlToUpload);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/octet-stream");
            con.setRequestProperty("Authorization", "Token "+token);

            try (OutputStream out = con.getOutputStream()) {
                copy(in, out);
                out.flush();
            }

            int responseCode = con.getResponseCode();
            System.out.println("Response Code...: " + responseCode);
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, "Server returned non-OK code: {0}", responseCode);
            }

        } catch (MalformedURLException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     *
     * @param UrlToDownload
     * @return
     */
    public static byte[] downloadFromUrl(String UrlToDownload, String token) {
        ByteArrayOutputStream outputStream = null;
        try {
            System.out.println("br.gov.serpro.certificate.ui.util.Utils.downloadFromUrl()");
            URL url = new URL(UrlToDownload);
            outputStream = new ByteArrayOutputStream();
            byte[] chunk = new byte[BUFFER_SIZE];
            int bytesRead;
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestProperty("Authorization", "Token "+token);
            int responseCode = con.getResponseCode();
            System.out.println("Response Code...: " + responseCode);
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, "Server returned non-OK code: {0}", responseCode);
                throw new ConectionException("Server returned non-OK code: " + responseCode);
            }
            else {
                InputStream stream = con.getInputStream();
                
                while ((bytesRead = stream.read(chunk)) > 0) {
                    outputStream.write(chunk, 0, bytesRead);
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return outputStream.toByteArray();
    }

    /**
     * Read the given binary file, and return its contents as a byte array.
     *
     * @param file Caminho e nome do arquivo
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
                    int bytesRead = in.read(result, totalBytesRead, bytesRemaining);
                    if (bytesRead > 0) {
                        totalBytesRead = totalBytesRead + bytesRead;
                    }
                }

            } finally {
                in.close();
            }
        } catch (FileNotFoundException ex) {
            System.out.println(ex.getMessage());
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        return result;
    }

    /**
     *
     * @param content Conteudo a ser gravado
     * @param file Caminho e nome do arquivo
     */
    public static void writeContentToDisk(byte[] content, String file) {
        try {
            File f = new File(file);
            FileOutputStream os = new FileOutputStream(f);
            os.write(content);
            os.flush();
            os.close();
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    /**
     *
     * @param input
     * @param output
     * @return
     * @throws IOException
     */
    private static long copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        long count = 0L;
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    /**
     * Create a random 1024 bit RSA key pair
     *
     * @return
     * @throws java.lang.Exception
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048, new SecureRandom());
        return kpGen.generateKeyPair();
    }

    /**
     * Converts a {@link X509Certificate} instance into a Base-64 encoded string
     * (PEM format).
     *
     * @param x509Cert A X509 Certificate instance
     * @return PEM formatted String
     * @throws java.io.IOException
     */
    public static String convertToBase64PEMString(Certificate x509Cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (PEMWriter pw = new PEMWriter(sw)) {
            pw.writeObject(x509Cert);
        }
        return sw.toString();
    }

    public static PublicKey reconstructPublicKey(String algorithm, byte[] pub_key) {
        PublicKey public_key = null;

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");
            EncodedKeySpec pub_key_spec = new X509EncodedKeySpec(pub_key);
            public_key = kf.generatePublic(pub_key_spec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm oculd not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return public_key;
    }

}
