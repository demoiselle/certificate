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

import java.util.Collection;
import java.util.HashSet;

/**
 * SignaturePolicyId ::= SEQUENCE { sigPolicyId SigPolicyId, sigPolicyHash
 * SigPolicyHash, sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF
 * SigPolicyQualifierInfo OPTIONAL}
 * 
 *
 * @deprecated replaced by Demoiselle SIGNER
 * @see <a href="https://github.com/demoiselle/signer">https://github.com/demoiselle/signer</a>
 * 
 */
@Deprecated
public class SignaturePolicyId {

	private String sigPolicyId;
	private String hashAlgorithm;
	private byte[] hash;
	private Collection<SigPolicyQualifierInfo> sigPolicyQualifiers;

	public String getSigPolicyId() {
		return this.sigPolicyId;
	}

	public void setSigPolicyId(String SigPolicyId) {
		this.sigPolicyId = SigPolicyId;
	}

	public String getHashAlgorithm() {
		return hashAlgorithm;
	}

	public void setHashAlgorithm(String hashAlgorithm) {
		this.hashAlgorithm = hashAlgorithm;
	}

	public byte[] getHash() {
		return hash;
	}

	public void setHash(byte[] hash) {
		this.hash = hash;
	}

	public Collection<SigPolicyQualifierInfo> getSigPolicyQualifiers() {
		return sigPolicyQualifiers;
	}

	public void setSigPolicyQualifiers(Collection<SigPolicyQualifierInfo> sigPolicyQualifiers) {
		this.sigPolicyQualifiers = sigPolicyQualifiers;
	}

	public void addSigPolicyQualifiers(SigPolicyQualifierInfo sigPolicyQualifiers) {
		if (this.sigPolicyQualifiers == null) {
			this.sigPolicyQualifiers = new HashSet<SigPolicyQualifierInfo>();
		}
		this.sigPolicyQualifiers.add(sigPolicyQualifiers);
	}

}
