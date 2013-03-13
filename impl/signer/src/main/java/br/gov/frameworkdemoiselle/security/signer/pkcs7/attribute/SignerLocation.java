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

package br.gov.frameworkdemoiselle.security.signer.pkcs7.attribute;

/**
 * id-aa-ets-signerLocation OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 17}
 * 
 * Signer-location attribute values have ASN.1 type SignerLocation:
 * 
 * SignerLocation ::= SEQUENCE { -- at least one of the following shall be
 * present: countryName [0] DirectoryString OPTIONAL, -- As used to name a
 * Country in X.500 localityName [1] DirectoryString OPTIONAL, -- As used to
 * name a locality in X.500 postalAdddress [2] PostalAddress OPTIONAL }
 * 
 * PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
 * 
 * @author 09275643784
 * 
 */
public class SignerLocation implements SignedAttribute {

	private final String localityName;

	public SignerLocation(String localityName) {
		this.localityName = localityName;
	}

	@Override
	public String getOID() {
		return "1.2.840.113549.1.9.16.2.17";
	}

	@Override
	public String getValue() {
		return this.localityName;
	}

}
