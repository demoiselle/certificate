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

import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.Attribute;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public enum BCAdapter {

    MessageDigest(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.MessageDigest.class, BCMessageDigest.class),
    SigningTime(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigningTime.class, BCSigningTime.class),
    SignaturePolicyIdentifier(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignaturePolicyIdentifier.class, BCSignaturePolicyIdentifier.class),
    FileName(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.FileName.class, BCFileName.class),
    SigningCertificate(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigningCertificate.class, BCSigningCertificate.class),
    SigningCertificateV2(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SigningCertificateV2.class, BCSigningCertificateV2.class),
    SignerLocation(br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute.SignerLocation.class, BCSignerLocation.class);

    private Class<? extends Attribute> attributeClass;
    private Class<? extends BCAttribute> bcAttributeClass;

    private BCAdapter(Class<? extends Attribute> attributeClass, Class<? extends BCAttribute> bcAttributeClass) {
        this.attributeClass = attributeClass;
        this.bcAttributeClass = bcAttributeClass;
    }

    public static BCAttribute factoryBCAttribute(Attribute attribute) {
        if (attribute == null) {
            return null;
        }
        BCAdapter[] values = BCAdapter.values();
        for (BCAdapter value : values) {
            if (attribute.getClass().equals(value.attributeClass)) {
                Class<? extends BCAttribute> clazz = value.bcAttributeClass;
                try {
                    Constructor<? extends BCAttribute> constructor = clazz.getConstructor(attribute.getClass());
                    BCAttribute object = constructor.newInstance(attribute);
                    return object;
                } catch (IllegalAccessException | IllegalArgumentException | InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException e) {
                    return null;
                }
            }
        }
        return null;
    }
}
