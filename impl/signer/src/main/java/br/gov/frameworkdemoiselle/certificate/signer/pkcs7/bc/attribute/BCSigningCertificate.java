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
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.attribute;

import br.gov.frameworkdemoiselle.certificate.criptography.Digest;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.criptography.factory.DigestFactory;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigningCertificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.X509Name;

public class BCSigningCertificate extends BCSignedAttribute {

    public BCSigningCertificate(SigningCertificate signingCertificate) {
        super(signingCertificate);
    }

    @Override
    public ASN1Set getValue() {
        SigningCertificate attribute = (SigningCertificate) super.getAttribute();
        X509Certificate cert = attribute.getValue();
        Digest digest = DigestFactory.getInstance().factoryDefault();
        digest.setAlgorithm(DigestAlgorithmEnum.SHA_1);
        byte[] certHash = null;
        try {
            certHash = digest.digest(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            ex.printStackTrace();
        }
        X509Name dirName = new X509Name(cert.getSubjectDN().getName());
        GeneralName name = new GeneralName(dirName);
        GeneralNames issuer = new GeneralNames(name);
        DERInteger serialNumber = new DERInteger(cert.getSerialNumber());
        IssuerSerial issuerSerial = new IssuerSerial(issuer, serialNumber);
        ESSCertID essCertId = new ESSCertID(certHash, issuerSerial);
        //return new DERSet(new ASN1Encodable[]{new DERSet(essCertId), new DERSet(new DERNull())});
        return new DERSet(new DERSequence(new ASN1Encodable[]{new DERSequence(essCertId), new DERSequence(new DERNull())}));
    }
}
