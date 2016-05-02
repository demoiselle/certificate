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

import br.gov.frameworkdemoiselle.certificate.oid.OIDGeneric;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_1;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_2;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_3;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_4;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_5;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_6;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_7;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_8;
import br.gov.frameworkdemoiselle.certificate.oid.OID_2_16_76_1_3_9;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Class Certificate Extra <br>
 * <br>
 *
 * Extra Informations for ICP-BRASIL (DOC-ICP-04) Certificates. Abstracts the
 * rules to PESSOA FISICA, PESSOA JURIDICA and EQUIPAMENTO/APLICAÇÃO
 *
 * @author CETEC/CTCTA
 */
public class CertificateExtra {

    private static final Logger LOGGER = Logger.getLogger(CertificateExtra.class.getName());

    private static final Integer ZERO = 0;
    private static final Integer UM = 1;
    private String email = null;
    private final Map<String, OIDGeneric> extras = new HashMap<String, OIDGeneric>(0);

    /**
     *
     * @param certificate
     */
    public CertificateExtra(X509Certificate certificate) {
        try {
            if (certificate.getSubjectAlternativeNames() == null) {
                return;
            }
            for (List<?> list : certificate.getSubjectAlternativeNames()) {
                if (list.size() != 2) {
                    throw new Exception("O tamanho das informações extras do certificado está incorreto");
                }

                Object object1, object2;

                object1 = list.get(0);
                object2 = list.get(1);

                if (!(object1 instanceof Integer)) {
                    throw new Exception("O valor não é do tipo \"java.lang.Integer\"");
                }

                Integer tipo = (Integer) object1;

                if (tipo.equals(ZERO)) {
                    byte[] data = (byte[]) object2;
                    OIDGeneric oidGeneric = OIDGeneric.getInstance(data);
                    extras.put(oidGeneric.getOid(), oidGeneric);
                } else if (tipo.equals(UM)) {
                    email = (String) object2;
                }
            }
        } catch (CertificateParsingException ex) {
            LOGGER.info(ex.getMessage());
        } catch (Exception ex) {
            LOGGER.info(ex.getMessage());
        }
    }

    /**
     * Check if it is "ICP-BRASIL Pessoa Fisica" Certificate
     *
     * @return
     */
    public boolean isCertificatePF() {
        return extras.get("2.16.76.1.3.1") != null;
    }

    /**
     * Check if it is "ICP-BRASIL Pessoa Juridica" Certificate
     *
     * @return
     */
    public boolean isCertificatePJ() {
        return extras.get("2.16.76.1.3.7") != null;
    }

    /**
     * Check if it is "ICP-BRASIL Equipment" Certificate
     *
     * @return
     */
    public boolean isCertificateEquipment() {
        return extras.get("2.16.76.1.3.8") != null;
    }

    /**
     * Class OID 2.16.76.1.3.1 <br>
     * <br>
     * Has some "ICP-BRASIL Pessoa Fisica" attributes<br>
     * <b>*</b> Data de nascimento do titular "DDMMAAAA" <br>
     * <b>*</b> Cadastro de pessoa fisica (CPF) do titular <br>
     * <b>*</b> Numero de Identidade Social - NIS (PIS, PASEP ou CI) <br>
     * <b>*</b> Numero do Registro Geral (RG) do titular <br>
     * <b>*</b> Sigla do orgao expedidor do RG <br>
     * <b>*</b> UF do orgao expedidor do RG <br>
     *
     * @return OID_2_16_76_1_3_1
     */
    public OID_2_16_76_1_3_1 getOID_2_16_76_1_3_1() {
        return (OID_2_16_76_1_3_1) extras.get("2.16.76.1.3.1");
    }

    /**
     * Class OID 2.16.76.1.3.5 <br>
     * <br>
     * Has some "ICP-BRASIL Fisica" attributes<br>
     * <b>*</b> Numero de inscricao do Titulo de Eleitor <br>
     * <b>*</b> Zona Eleitoral <br>
     * <b>*</b> Secao <br>
     * <b>*</b> Municipio do titulo <br>
     * <b>*</b> UF do titulo <br>
     *
     * @return OID_2_16_76_1_3_5
     */
    public OID_2_16_76_1_3_5 getOID_2_16_76_1_3_5() {
        return (OID_2_16_76_1_3_5) extras.get("2.16.76.1.3.5");
    }

    /**
     * Class OID 2.16.76.1.3.6 <br>
     * <br>
     * Has some "ICP-BRASIL Pessoa Fisica" attributes<br>
     * <b>*</b> Numero do Cadastro Especifico do INSS (CEI) da pessoa fisica
     * titular do certificado <br>
     *
     * @return OID_2_16_76_1_3_6
     */
    public OID_2_16_76_1_3_6 getOID_2_16_76_1_3_6() {
        return (OID_2_16_76_1_3_6) extras.get("2.16.76.1.3.6");
    }

    /**
     * Class OID 2.16.76.1.3.2 <br>
     * <br>
     * Has some "ICP-BRASIL Pessoa Juridica and Equipment" attributes<br>
     * <b>*</b> Nome do responsavel pelo certificado <br>
     *
     * @return OID_2_16_76_1_3_2
     */
    public OID_2_16_76_1_3_2 getOID_2_16_76_1_3_2() {
        return (OID_2_16_76_1_3_2) extras.get("2.16.76.1.3.2");
    }

    /**
     * Class OID 2.16.76.1.3.3 <br>
     * <br>
     * Has some "ICP-BRASIL Pessoa Juridica and Equipment" attributes<br>
     * <b>*</b> Cadastro Nacional de Pessoa Juridica (CNPJ) da pessoa juridica
     * titular do certificado <br>
     *
     * @return OID_2_16_76_1_3_3
     */
    public OID_2_16_76_1_3_3 getOID_2_16_76_1_3_3() {
        return (OID_2_16_76_1_3_3) extras.get("2.16.76.1.3.3");
    }

    /**
     * Class OID 2.16.76.1.3.4 <br>
     * <br>
     * Has some "ICP-BRASIL Pessoa Juridica and Equipment" attributes<br>
     * <b>*</b> Data de nascimento do titular "DDMMAAAA" <br>
     * <b>*</b> Cadastro de pessoa fisica (CPF) do titular <br>
     * <b>*</b> Numero de Identidade Social - NIS (PIS, PASEP ou CI) <br>
     * <b>*</b> Numero do Registro Geral (RG) do titular <br>
     * <b>*</b> Sigla do orgao expedidor do RG <br>
     * <b>*</b> UF do orgao expedidor do RG <br>
     *
     * @return OID_2_16_76_1_3_4
     */
    public OID_2_16_76_1_3_4 getOID_2_16_76_1_3_4() {
        return (OID_2_16_76_1_3_4) extras.get("2.16.76.1.3.4");
    }

    /**
     * Class OID 2.16.76.1.3.7 <br>
     * <br>
     * Has some "ICP-BRASIL Pessoa Juridica" attributes<br>
     * <b>*</b> Numero do Cadastro Especifico do INSS (CEI) da pessoa juridica
     * titular do certificado <br>
     *
     * @return OID_2_16_76_1_3_7
     */
    public OID_2_16_76_1_3_7 getOID_2_16_76_1_3_7() {
        return (OID_2_16_76_1_3_7) extras.get("2.16.76.1.3.7");
    }

    /**
     * Class OID 2.16.76.1.3.8 <br>
     * <br>
     * Has some "ICP-BRASIL Equipment" attributes<br>
     * <b>*</b> Nome empresarial constante do Cadastro Nacional de Pessoa
     * Juridica (CNPJ), sem abreviacoes, se o certificado for de pessoa
     * juridica<br>
     *
     * @return OID_2_16_76_1_3_8
     */
    public OID_2_16_76_1_3_8 getOID_2_16_76_1_3_8() {
        return (OID_2_16_76_1_3_8) extras.get("2.16.76.1.3.8");
    }

    /**
     *
     * @return
     */
    public OID_2_16_76_1_3_9 getOID_2_16_76_1_3_9() {
        return (OID_2_16_76_1_3_9) extras.get("2.16.76.1.3.9");
    }

    /**
     *
     * @return the e-mail for certificate.
     */
    public String getEmail() {
        return email;
    }

}
