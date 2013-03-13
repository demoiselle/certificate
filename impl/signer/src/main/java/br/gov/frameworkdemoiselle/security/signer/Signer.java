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

package br.gov.frameworkdemoiselle.security.signer;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Especificação básica para implementação de assinaturas digitais.
 */
public interface Signer {

	/**
	 * Indica qual o Provider será utilizado.
	 */
	abstract public void setProvider(Provider provider);

	/**
	 * Chave privada necessária para a criptografia assimétrica
	 */
	abstract public void setPrivateKey(PrivateKey privateKey);

	/**
	 * Chave publica necessária para a criptografia assimétrica
	 */
	abstract public void setPublicKey(PublicKey publicKey);

	/**
	 * Algoritmo de Assinatura. Ex: SHA1withRSA
	 */
	abstract public void setAlgorithm(String algorithm);

	/**
	 * Algoritmo pré-defido no enum. Compatíveis com ICP-Brasil
	 */
	abstract public void setAlgorithm(SignerAlgorithmEnum algorithm);

	/**
	 * Método de assinatura digital.
	 */
	abstract public byte[] signer(byte[] content);

	/**
	 * Método de validação da assinatura.
	 */
	abstract public boolean check(byte[] content, byte[] signed);

	/**
	 * Retorna o provider.
	 */
	abstract public Provider getProvider();

	/**
	 * Retorna a chave privada.
	 */
	abstract public PrivateKey getPrivateKey();

	/**
	 * Retorna o algoritmo.
	 */
	abstract public String getAlgorithm();

	/**
	 * Retorna a chave publica.
	 */
	abstract public PublicKey getPublicKey();

}
