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
package br.gov.frameworkdemoiselle.certificate.signer.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.gov.frameworkdemoiselle.certificate.ca.manager.CAManager;
import br.gov.frameworkdemoiselle.certificate.signer.SignerException;

public class ValidadorUtil {

    public enum CertPathEncoding {

        PKCS7, PkiPath
    }

    /**
     * Valida uma assinatura digital ou um certificado digital tomando por base
     * o certificado raiz da ICP-Brasil
     *
     * @param contentSigned
     * @param trustedCa
     * @param encoding
     * @throws SignerException
     */
    public static void validate(byte[] contentSigned, String policyOID, CertPathEncoding encoding) throws SignerException {
        X509Certificate userCertificate = null;
        Collection<X509Certificate> trustedCas = CAManager.getInstance().getSignaturePolicyRootCAs(policyOID);
        try {

            CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
            InputStream in = new ByteArrayInputStream(new byte[512]);

            Security.addProvider(new BouncyCastleProvider());
            in = new ByteArrayInputStream(contentSigned);
            CertPath certPath = null;

            switch (encoding) {
                case PKCS7:
                    certPath = factory.generateCertPath(in, "PKCS7");
                    break;

                case PkiPath:
                    certPath = factory.generateCertPath(in, "PkiPath");
                    break;
            }

            userCertificate = (X509Certificate) certPath.getCertificates().iterator().next();

            // Carrega os certificados confiaveis
            List<TrustAnchor> trustAnchors = new ArrayList<TrustAnchor>();
            for (X509Certificate x : trustedCas) {
                trustAnchors.add(new TrustAnchor(x, null));
            }

            Set trust = new HashSet();
            Collections.addAll(trust, trustAnchors.toArray());

            // Create the parameters for the validator
            PKIXParameters params = new PKIXParameters(trust);

            params.setSigProvider("BC");
            params.setRevocationEnabled(false);
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            CertPathValidatorResult result = certPathValidator.validate(certPath, params);

            // Get the CA used to validate this path
            PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult) result;
            TrustAnchor trustAnchor = pkixResult.getTrustAnchor();
            X509Certificate cert = trustAnchor.getTrustedCert();

        } catch (Throwable error) {
            error.printStackTrace();
//            if (error.getCause() instanceof CertificateExpiredException) {
//                throw new SignerException("O certificado de uma das cadeias está expirado", error);
//            }

            try {
                CAManager.getInstance().validateRootCAs(trustedCas, userCertificate);
            } catch (Throwable managerError) {
                managerError.printStackTrace();
                throw new SignerException("Este certificado nao esta associado a uma cadeia confiavel de ACs", error);
            }
        }
    }

    public static void validate(X509Certificate certificate) {
        /*
         * Assinaturas digitais geradas segundo esta Política de Assinatura 
         * deverão ser criadas com chave privada associada ao certificado 
         * ICP-Brasil tipo A1 (do OID 2.16.76.1.2.1.1 ao OID 2.16.76.1.2.1.100),
         * tipo A2 (do OID 2.16.76.1.2.2.1 ao OID 2.16.76.1.2.2.100), do tipo A3 (do
         * OID 2.16.76.1.2.3.1 ao OID 2.16.76.1.2.3.100) e do tipo A4 
         * (do OID 2.16.76.1.2.4.1 ao OID 2.16.76.1.2.4.100), 
         * conforme definido em DOC-ICP-04.
         */

        try {
            byte[] val1 = certificate.getExtensionValue("2.5.29.32");
            ASN1InputStream ans1InputStream = new ASN1InputStream(new ByteArrayInputStream(val1));
            DERObject derObject = ans1InputStream.readObject();
            ans1InputStream.close();
            DEROctetString derOctetString = (DEROctetString) derObject;
            byte[] val2 = derOctetString.getOctets();
            ASN1InputStream asn1InputStream2 = new ASN1InputStream(new ByteArrayInputStream(val2));
            DERObject derObject2 = asn1InputStream2.readObject();
            asn1InputStream2.close();
            DERSequence derSequence = (DERSequence) derObject2;
            DERSequence derObject3 = (DERSequence) derSequence.getObjectAt(0).getDERObject();
            DERObjectIdentifier objectIdentifier = (DERObjectIdentifier) derObject3.getObjectAt(0);
            String identificador = objectIdentifier.toString();

            if (!(identificador.startsWith("2.16.76.1.2.1.") || identificador.startsWith("2.16.76.1.2.2.") || identificador.startsWith("2.16.76.1.2.3.") || identificador.startsWith("2.16.76.1.2.4."))) {
                throw new SignerException("O OID não corresponde a uma Política de Certificado.");
            }

            int sufixo = Integer.parseInt(identificador.substring(identificador.lastIndexOf(".") + 1));
            if (sufixo < 1 || sufixo > 100) {
                throw new SignerException("O certificado deve ser do tipo A1, A2, A3 ou A4.");
            }

        } catch (Throwable error) {
            throw new SignerException("A assinaturas digital deve ser criada com chave privada associada ao certificado ICP-Brasil tipo A1, A2, A3 ou A4", error);
        }
    }
}
