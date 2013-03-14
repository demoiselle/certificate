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

package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute;

/**
 * id-spq-ets-unotice OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 * rsadsi(113549) pkcs(1) pkcs9(9) smime(16) id-spq(5) 2 }
 * 
 * SPUserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL, explicitText
 * DisplayText OPTIONAL}
 * 
 * NoticeReference ::= SEQUENCE {
 * 
 * organization DisplayText, noticeNumbers SEQUENCE OF INTEGER }
 * 
 * DisplayText ::= CHOICE { visibleString VisibleString (SIZE (1..200)),
 * bmpString BMPString (SIZE (1..200)), utf8String UTF8String (SIZE (1..200)) }
 * 
 * 
 * TODO: Implementar sequencias de NoticeReference
 * 
 */
public class SigPolicyQualifierInfoUserNotice extends SigPolicyQualifierInfo {

	private String organization = null;
	private Integer[] noticeNumbers = null;
	private String explicitText = null;

	@Override
	public String getOID() {
		return "1.2.840.113549.1.9.16.5.2";
	}

	public SigPolicyQualifierInfoUserNotice() {
	}

	@Override
	public SigPolicyQualifierInfoUserNotice getValue() {
		return this;
	}

	public String getOrganization() {
		return organization;
	}

	public void setOrganization(String organization) {
		this.organization = organization;
	}

	public Integer[] getNoticeNumbers() {
		return noticeNumbers;
	}

	public void setNoticeNumbers(Integer[] noticeNumbers) {
		this.noticeNumbers = noticeNumbers;
	}

	public String getExplicitText() {
		return explicitText;
	}

	public void setExplicitText(String explicitText) {
		this.explicitText = explicitText;
	}

}
