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

package br.gov.frameworkdemoiselle.security.certificate.extension;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;

import br.gov.frameworkdemoiselle.security.certificate.CertificateException;
import br.gov.frameworkdemoiselle.security.certificate.IOIDExtensionLoader;

public class DefaultExtensionLoader implements IOIDExtensionLoader {

	@Override
	public void load(Object object, Field field, X509Certificate x509) {
		if (field.isAnnotationPresent(DefaultExtension.class)) {
			DefaultExtension annotation = field.getAnnotation(DefaultExtension.class);

			Object keyValue;

			BasicCertificate cert = new BasicCertificate(x509);

			switch (annotation.type()) {
			case CRL_URL:
				try {
					keyValue = cert.getCRLDistributionPoint();
				} catch (IOException e1) {
					throw new CertificateException("Error on get value to field " + field.getName(), e1);
				}
				break;
			case SERIAL_NUMBER:
				keyValue = cert.getSerialNumber();
				break;
			case ISSUER_DN:
				try {
					keyValue = cert.getCertificateIssuerDN().toString();
				} catch (IOException e1) {
					throw new CertificateException("Error on get value to field " + field.getName(), e1);
				}
				break;
			case SUBJECT_DN:
				try {
					keyValue = cert.getCertificateSubjectDN().toString();
				} catch (IOException e1) {
					throw new CertificateException("Error on get value to field " + field.getName(), e1);
				}
				break;
			case KEY_USAGE:
				keyValue = cert.getICPBRKeyUsage().toString();
				break;
			case PATH_LENGTH:
				keyValue = cert.getPathLength();
				break;
			case AUTHORITY_KEY_IDENTIFIER:
				try {
					keyValue = cert.getAuthorityKeyIdentifier();
				} catch (IOException e1) {
					throw new CertificateException("Error on get value to field " + field.getName(), e1);
				}
				break;

			case SUBJECT_KEY_IDENTIFIER:
				try {
					keyValue = cert.getSubjectKeyIdentifier();
				} catch (IOException e1) {
					throw new CertificateException("Error on get value to field " + field.getName(), e1);
				}
				break;

			case BEFORE_DATE:
				keyValue = cert.getBeforeDate();
				break;
			case AFTER_DATE:
				keyValue = cert.getAfterDate();
				break;
			case CERTIFICATION_AUTHORITY:
				keyValue = cert.isCertificadoAc();
				break;

			default:
				throw new CertificateException(annotation.type() + " Not Implemented");
			}

			try {
				field.setAccessible(true);
				field.set(object, keyValue);
			} catch (Exception e) {
				throw new CertificateException("Error on load value in field " + field.getName(), e);
			}
		}
	}

}
