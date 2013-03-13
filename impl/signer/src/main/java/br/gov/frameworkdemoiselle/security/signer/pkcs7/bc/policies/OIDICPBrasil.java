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

package br.gov.frameworkdemoiselle.security.signer.pkcs7.bc.policies;

public interface OIDICPBrasil {

	public static final String PREFIX_POLICE_ID = "2.16.76.1.7.1.";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO CMS,
	// versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.1.
	public static final String POLICY_ID_AD_RB_CMS_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "1.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO CMS,
	// versao 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.1.1.
	public static final String POLICY_ID_AD_RB_CMS_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "1.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO CMS,
	// versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.
	public static final String POLICY_ID_AD_RB_CMS_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "1.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO CMS,
	// versao 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.1.2.1.
	public static final String POLICY_ID_AD_RB_CMS_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "1.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// CMS,
	// versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.1.
	public static final String POLICY_ID_AD_RT_CMS_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "2.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// CMS,
	// versao 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.1.1.
	public static final String POLICY_ID_AD_RT_CMS_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "2.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// CMS,
	// versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.
	public static final String POLICY_ID_AD_RT_CMS_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "2.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// CMS,
	// versao 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.2.2.1.
	public static final String POLICY_ID_AD_RT_CMS_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "2.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// CMS, versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.1.
	public static final String POLICY_ID_AD_RV_CMS_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "3.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// CMS, versao 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.1.1.
	public static final String POLICY_ID_AD_RV_CMS_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "3.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// CMS, versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.
	public static final String POLICY_ID_AD_RV_CMS_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "3.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// CMS, versao 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.3.2.1.
	public static final String POLICY_ID_AD_RV_CMS_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "3.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// CMS,
	// versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.1.
	public static final String POLICY_ID_AD_RC_CMS_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "4.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// CMS,
	// versao 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.1.1.
	public static final String POLICY_ID_AD_RC_CMS_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "4.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// CMS,
	// versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.
	public static final String POLICY_ID_AD_RC_CMS_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "4.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// CMS,
	// versao 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.4.2.1.
	public static final String POLICY_ID_AD_RC_CMS_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "4.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO CMS, versao 1.0 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.5.1.
	public static final String POLICY_ID_AD_RA_CMS_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "5.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO CMS, versao 1.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.5.1.1.
	public static final String POLICY_ID_AD_RA_CMS_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "5.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO CMS, versao 2.0 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.5.2.
	public static final String POLICY_ID_AD_RA_CMS_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "5.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO CMS, versao 2.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.5.2.1.
	public static final String POLICY_ID_AD_RA_CMS_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "5.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO
	// XML-DSig,
	// versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.1.
	public static final String POLICY_ID_AD_RB_XML_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "6.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO
	// XML-DSig,
	// versao 1.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.1.1.
	public static final String POLICY_ID_AD_RB_XML_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "6.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO
	// XML-DSig,
	// versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.
	public static final String POLICY_ID_AD_RB_XML_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "6.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA BASICA NO FORMATO
	// XML-DSig,
	// versao 2.1 e o seu Object Identifier (OID) é 2.16.76.1.7.1.6.2.1.
	public static final String POLICY_ID_AD_RB_XML_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "6.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// XML-DSig, versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.1.
	public static final String POLICY_ID_AD_RT_XML_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "7.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// XML-DSig, versao 1.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.7.1.1.
	public static final String POLICY_ID_AD_RT_XML_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "7.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// XML-DSig, versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.7.2.
	public static final String POLICY_ID_AD_RT_XML_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "7.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIA DO TEMPO NO FORMATO
	// XML-DSig, versao 2.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.7.2.1.
	public static final String POLICY_ID_AD_RT_XML_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "7.1.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// XML-DSig, versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.1.
	public static final String POLICY_ID_AD_RV_XML_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "8.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// XML-DSig, versao 1.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.8.1.1.
	public static final String POLICY_ID_AD_RV_XML_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "8.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// XML-DSig, versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.8.2.
	public static final String POLICY_ID_AD_RV_XML_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "8.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA VALIDACAO NO
	// FORMATO
	// XML-DSig, versao 2.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.8.2.1.
	public static final String POLICY_ID_AD_RV_XML_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "8.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// XMLDSig, versao 1.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.1.
	public static final String POLICY_ID_AD_RC_XML_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "9.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// XMLDSig, versao 1.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.9.1.1.
	public static final String POLICY_ID_AD_RC_XML_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "9.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// XMLDSig, versao 2.0 e o seu Object Identifier (OID) é 2.16.76.1.7.1.9.2.
	public static final String POLICY_ID_AD_RC_XML_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "9.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS COMPLETAS NO FORMATO
	// XMLDSig, versao 2.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.9.2.1.
	public static final String POLICY_ID_AD_RC_XML_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "9.2.1";

	// O nome desta Política de Assinatura para a versão 1.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO XML-DSig, versao 1.0 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.10.1.
	public static final String POLICY_ID_AD_RA_XML_V_1_0 = OIDICPBrasil.PREFIX_POLICE_ID + "10.1";

	// O nome desta Política de Assinatura para a versão 1.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO XML-DSig, versao 1.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.10.1.1.
	public static final String POLICY_ID_AD_RA_XML_V_1_1 = OIDICPBrasil.PREFIX_POLICE_ID + "10.1.1";

	// O nome desta Política de Assinatura para a versão 2.0 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO XML-DSig, versao 2.0 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.10.2.
	public static final String POLICY_ID_AD_RA_XML_V_2_0 = OIDICPBrasil.PREFIX_POLICE_ID + "10.2";

	// O nome desta Política de Assinatura para a versão 2.1 é POLITICA
	// ICP-BRASIL PARA ASSINATURA DIGITAL COM REFERENCIAS PARA ARQUIVAMENTO NO
	// FORMATO XML-DSig, versao 2.1 e o seu Object Identifier (OID) é
	// 2.16.76.1.7.1.10.2.1.
	public static final String POLICY_ID_AD_RA_XML_V_2_1 = OIDICPBrasil.PREFIX_POLICE_ID + "10.2.1";
}