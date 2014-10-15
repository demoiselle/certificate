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
package br.gov.frameworkdemoiselle.certificate.extension;

import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_1;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_5;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_6;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_9;

/**
 * Implemented Class for ICP-BRASIL (DOC-ICP-04) "PESSOA FISICA" Certificates.
 *
 * @see ICPBRSubjectAlternativeNames
 */
public class ICPBRCertificatePF {

    private OID_2_16_76_1_3_1 oid_2_16_76_1_3_1 = null;
    private OID_2_16_76_1_3_5 oid_2_16_76_1_3_5 = null;
    private OID_2_16_76_1_3_6 oid_2_16_76_1_3_6 = null;
    private OID_2_16_76_1_3_9 oid_2_16_76_1_3_9 = null;

    /**
     *
     * @param oid1 = 2.16.76.1.3.1 e conteúdo = nas primeiras 8 (oito) posições,
     * a data de nascimento do titular, no formato ddmmaaaa; nas 11 (onze)
     * posições subsequentes, o Cadastro de Pessoa Física (CPF) do titular; nas
     * 11 (onze) posições subsequentes, o Número de Identificação Social - NIS
     * (PIS, PASEP ou CI); nas 15 (quinze) posições subsequentes, o número do
     * Registro Geral - RG do titular; nas 10 (dez) posições subsequentes, as
     * siglas do órgão expedidor do RG e respectiva UF
     *
     * @param oid2 OID = 2.16.76.1.3.5 e conteúdo = nas primeiras 12 (doze)
     * posições, o número de inscrição do Título de Eleitor; nas 3 (três)
     * posições subsequentes, a Zona Eleitoral; nas 4 (quatro) posições
     * seguintes, a Seção; nas 22 (vinte e duas) posições subsequentes, o
     * município e a UF do Título de Eleitor.
     *
     * @param oid3 OID = 2.16.76.1.3.6 e conteúdo = nas 12 (doze) posições o
     * número do Cadastro Especifico do INSS (CEI) da pessoa física titular do
     * certificado.
     *
     * @param oid4 OID = 2.16.76.1.3.9 e conteúdo = nas primeiras 11 (onze)
     * posições, o número de Registro de Identidade Civil.
     *
     */
    public ICPBRCertificatePF(OID_2_16_76_1_3_1 oid1, OID_2_16_76_1_3_5 oid2, OID_2_16_76_1_3_6 oid3, OID_2_16_76_1_3_9 oid4) {
        this.oid_2_16_76_1_3_1 = oid1;
        this.oid_2_16_76_1_3_5 = oid2;
        this.oid_2_16_76_1_3_6 = oid3;
        this.oid_2_16_76_1_3_9 = oid4;
    }

    /**
     *
     * @return o numero do Cadastro de Pessoa Fisica (CPF) do titular
     */
    public String getCPF() {
        return oid_2_16_76_1_3_1.getCPF();
    }

    /**
     *
     * @return data de nascimento do titular
     */
    public String getDataNascimento() {
        return oid_2_16_76_1_3_1.getDataNascimento();
    }

    /**
     *
     * @return o numero de Identificacao Social - NIS (PIS, PASEP ou CI)
     */
    public String getNis() {
        return oid_2_16_76_1_3_1.getNIS();
    }

    /**
     *
     * @return o numero do Registro Geral - RG do titular
     */
    public String getRg() {
        return oid_2_16_76_1_3_1.getRg();
    }

    /**
     *
     * @return as siglas do orgao expedidor do RG
     */
    public String getOrgaoExpedidorRg() {
        return oid_2_16_76_1_3_1.getOrgaoExpedidorRg();
    }

    /**
     *
     * @return a UF do orgao expedidor do RG
     */
    public String getUfExpedidorRg() {
        return oid_2_16_76_1_3_1.getUfExpedidorRg();
    }

    /**
     *
     * @return o numero de inscricao do Titulo de Eleitor
     */
    public String getTituloEleitor() {
        return oid_2_16_76_1_3_5.getTitulo();
    }

    /**
     *
     * @return o numero da Secao do Titulo de Eleitor
     */
    public String getSecaoTituloEleitor() {
        return oid_2_16_76_1_3_5.getSecao();
    }

    /**
     *
     * @return numero da Zona Eleitoral do Titulo de Eleitor
     */
    public String getZonaTituloEleitor() {
        return oid_2_16_76_1_3_5.getZona();
    }

    /**
     *
     * @return o municipio e a UF do Titulo de Eleitor
     *
     * public String getMunicipioUfTituloEleitor(){ return
     * oID_2_16_76_1_3_5.getMunicipioUf(); }
     */
    /**
     *
     * @return o municipio do Titulo de Eleitor
     */
    public String getMunicipioTituloEleitor() {
        return oid_2_16_76_1_3_5.getMunicipioTitulo();
    }

    /**
     *
     * @return a UF do Titulo de Eleitor
     */
    public String getUfTituloEleitor() {
        return oid_2_16_76_1_3_5.getUFTitulo();
    }

    /**
     *
     * @return o numero do Cadastro Especifico do INSS (CEI) da pessoa fisica
     * titular do certificado
     */
    public String getCEI() {
        return oid_2_16_76_1_3_6.getCEI();
    }

    /**
     * Retorna o RIC (REgistro de Identidade Civil)
     *
     * @return O Registro de Identidade Civil
     */
    public String getRIC() {
        return oid_2_16_76_1_3_9.getRegistroDeIdentidadeCivil();
    }

    /*
     * TODO - Campo opcional e nao obrigatorio campos otherName, não
     * obrigatórios, contendo: OID = 2.16.76.1.4.n e conteúdo = de tamanho
     * variavel correspondente ao número de habilitação ou identificação
     * profissional emitido por conselho de classe ou órgão competente. A AC
     * Raiz, por meio do documento ATRIBUICAO DE OID NA ICPBRASIL [2]
     * regulamentara a correspondência de cada conselho de classe ou órgão
     * competente ao conjunto de OID acima definido.
     */
}
