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
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.impl;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SigPolicyQualifiers;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignedAttribute;
import br.gov.frameworkdemoiselle.policy.engine.asn1.etsi.SignaturePolicy;

public class IdSigningPolicy implements SignedAttribute {

    private final String oid = "1.2.840.113549.1.9.16.2.15";
    private SignaturePolicy signaturePolicy = null;

    @Override
    public String getOID() {
        return oid;
    }

    @Override
    public Attribute getValue() {
        //Atributo 1
        ASN1ObjectIdentifier sigPolicyId = new ASN1ObjectIdentifier(signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier().getValue());

        //Atributo 2
        OtherHashAlgAndValue sigPolicyHash = new OtherHashAlgAndValue(new AlgorithmIdentifier(
        		new ASN1ObjectIdentifier(signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue())), 
        		signaturePolicy.getSignPolicyHash().getDerOctetString());

        //Atributo 3
        List<SigPolicyQualifierInfo> sigPolicyQualifierInfos = new ArrayList<SigPolicyQualifierInfo>();

        ASN1ObjectIdentifier sigPolicyQualifierId = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.5.1");
        DERIA5String sigQualifier = new DERIA5String(signaturePolicy.getSignPolicyURI());
        SigPolicyQualifierInfo bcSigPolicyQualifierInfo = new SigPolicyQualifierInfo(sigPolicyQualifierId, sigQualifier);
        sigPolicyQualifierInfos.add(bcSigPolicyQualifierInfo);

        SigPolicyQualifiers sigPolicyQualifiers = new SigPolicyQualifiers(sigPolicyQualifierInfos.toArray(new SigPolicyQualifierInfo[]{}));

        SignaturePolicyId signaturePolicyId = new SignaturePolicyId(sigPolicyId, sigPolicyHash, sigPolicyQualifiers);
        return new Attribute(new ASN1ObjectIdentifier(oid), new DERSet(signaturePolicyId));
    }

    @Override
    public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy) {
        this.signaturePolicy = signaturePolicy;
    }

}
