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

package br.gov.frameworkdemoiselle.security.certificate.repository;

/**
 * Entidade responsavel por guardar as configuracoes necessarias ao uso do
 * repositorio
 */
public class Configuration {

	/** Chave do System para definir modo online ou offline */
	public static final String MODE_ONLINE = "security.certificate.repository.online";

	/**
	 * Chave do System para definir local de armazenamento do arquivo de index
	 * das crls
	 */
	public static final String CRL_INDEX = "security.certificate.repository.crl.index";

	/**
	 * Chave do System para definir local de armazenamento do arquivo de index
	 * das crls
	 */
	public static final String CRL_PATH = "security.certificate.repository.crl.path";

	private String crlIndex;
	private String crlPath;
	private boolean isOnline;

	public static Configuration instance = new Configuration();

	/**
	 * Verifica se há variavéis no System. Caso haja, seta nas variaveis de
	 * classes do contrário usa os valores padrões
	 */
	private Configuration() {
		String mode_online = (String) System.getProperties().get(MODE_ONLINE);
		if (mode_online == null || mode_online.equals("")) {
			setOnline(true);
		} else {
			setOnline(Boolean.valueOf(mode_online));
		}
		crlIndex = (String) System.getProperties().get(CRL_INDEX);
		if (crlIndex == null || crlIndex.equals("")) {
			setCrlIndex(".crl_index");
		}

		crlPath = (String) System.getProperties().get(CRL_PATH);
		if (crlPath == null || crlPath.equals("")) {
			setCrlPath("/tmp/crls");
		}
	}

	/**
	 * Retorna instância única
	 * 
	 * @return
	 */
	public static Configuration getInstance() {
		return instance;
	}

	/**
	 * Retorna o local onde está armazenado o arquivo de indice de crl
	 * 
	 * @return
	 */
	public String getCrlIndex() {
		return crlIndex;
	}

	/**
	 * Modificador padrão
	 * 
	 * @param crlIndex
	 */
	public void setCrlIndex(String crlIndex) {
		this.crlIndex = crlIndex;
	}

	/**
	 * Retorna se o repositório está no modo online ou offline
	 * 
	 * @return se true (online) se false (offline)
	 */
	public boolean isOnline() {
		return isOnline;
	}

	/**
	 * Modificador padrão
	 * 
	 * @param isOnline
	 */
	public void setOnline(boolean isOnline) {
		this.isOnline = isOnline;
	}

	/**
	 * Caminho onde será armazenado o repositório de CRLs
	 * 
	 * @return
	 */
	public String getCrlPath() {
		return crlPath;
	}

	/**
	 * Modificador padrão
	 * 
	 * @param crlPath
	 */
	public void setCrlPath(String crlPath) {
		this.crlPath = crlPath;
	}

}
