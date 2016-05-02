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
package br.gov.frameworkdemoiselle.certificate.oid;

import java.util.logging.Logger;

/**
 * OID = 2.16.76.1.3.8 e conteúdo = nome empresarial constante do CNPJ (Cadastro
 * Nacional de Pessoa Jurídica), sem abreviações, se o certificado for de pessoa
 * jurídica;
 *
 * @author Humberto Pacheco - SERVICO FEDERAL DE PROCESSAMENTO DE DADOS
 */
public class OID_2_16_76_1_3_8 extends OIDGeneric {

    private static final Logger LOGGER = Logger.getLogger(OID_2_16_76_1_3_8.class.getName());

    public static final String OID = "2.16.76.1.3.8";

    public OID_2_16_76_1_3_8() {
    }

    @Override
    public void initialize() {

    }

    /**
     * Retorna o nome empresarial constante do CNPJ (Cadastro Nacional de Pessoa
     * Jurídica), sem abreviações, se o certificado for de pessoa jurídica
     *
     * @return O nome empresarial constante do Cadastro Nacional de Pessoa
     * Juridica (CNPJ)
     */
    public String getNome() {
        return super.getData();
    }

}
