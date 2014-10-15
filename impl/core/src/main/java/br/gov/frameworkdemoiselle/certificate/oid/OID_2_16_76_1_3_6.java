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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OID = 2.16.76.1.3.6 e conteúdo = nas 12 (doze) posições o número do Cadastro
 * Especifico do INSS (CEI) da pessoa física titular do certificado
 *
 * @author Humberto Pacheco - SERVICO FEDERAL DE PROCESSAMENTO DE DADOS
 */
public class OID_2_16_76_1_3_6 extends OIDGeneric {

    private static final Logger logger = LoggerFactory.getLogger(OID_2_16_76_1_3_6.class);

    public static final String OID = "2.16.76.1.3.6";

    protected static final Object CAMPOS[] = {"CEI", 12};

    public OID_2_16_76_1_3_6() {

    }

    @Override
    public void initialize() {
        super.initialize(CAMPOS);
    }

    /**
     * Retorna o número do Cadastro Especifico do INSS (CEI) da pessoa física
     * titular do certificado
     *
     * @return O numero do cadastro no INSS(CEI).
     */
    public String getCEI() {
        return properties.get("CEI");
    }

}
