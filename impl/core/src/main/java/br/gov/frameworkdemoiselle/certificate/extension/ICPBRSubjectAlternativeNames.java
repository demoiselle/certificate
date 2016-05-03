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

import java.security.cert.X509Certificate;
import java.util.logging.Logger;

public class ICPBRSubjectAlternativeNames {

    private static final Logger LOGGER = Logger.getLogger(ICPBRSubjectAlternativeNames.class.getName());

    private String email = null;
    private ICPBRCertificatePF icpBRCertificatePF = null;
    private ICPBRCertificatePJ icpBRCertificatePJ = null;
    private ICPBRCertificateEquipment icpBRCertificateEquipment = null;

    /**
     *
     * @param certificate -> X509Certificate
     * @see java.security.cert.X509Certificate
     */
    public ICPBRSubjectAlternativeNames(X509Certificate certificate) {
        CertificateExtra certificateExtra = new CertificateExtra(certificate);
        if (certificateExtra.isCertificatePF()) {
            icpBRCertificatePF = new ICPBRCertificatePF(certificateExtra.getOID_2_16_76_1_3_1(), certificateExtra.getOID_2_16_76_1_3_5(), certificateExtra.getOID_2_16_76_1_3_6(), certificateExtra.getOID_2_16_76_1_3_9());
        } else if (certificateExtra.isCertificatePJ()) {
            icpBRCertificatePJ = new ICPBRCertificatePJ(certificateExtra.getOID_2_16_76_1_3_2(), certificateExtra.getOID_2_16_76_1_3_3(), certificateExtra.getOID_2_16_76_1_3_4(), certificateExtra.getOID_2_16_76_1_3_7());
        } else if (certificateExtra.isCertificateEquipment()) {
            icpBRCertificateEquipment = new ICPBRCertificateEquipment(certificateExtra.getOID_2_16_76_1_3_2(), certificateExtra.getOID_2_16_76_1_3_3(), certificateExtra.getOID_2_16_76_1_3_4(), certificateExtra.getOID_2_16_76_1_3_8());
        }
        this.email = certificateExtra.getEmail();
    }

    /**
     *
     * @return boolean
     */
    public boolean isCertificatePF() {
        return icpBRCertificatePF != null;
    }

    /**
     *
     * @return Object ICPBRCertificatePF
     * @see
     * br.gov.frameworkdemoiselle.certificate.extension.serpro.security.certificate.extension.ICPBRCertificatePF
     */
    public ICPBRCertificatePF getICPBRCertificatePF() {
        return icpBRCertificatePF;
    }

    /**
     *
     * @return boolean
     */
    public boolean isCertificatePJ() {
        return icpBRCertificatePJ != null;
    }

    /**
     *
     * @return Object ICPBRCertificatePJ
     * @see
     * br.gov.frameworkdemoiselle.certificate.extension.serpro.security.certificate.extension.ICPBRCertificatePJ
     */
    public ICPBRCertificatePJ getICPBRCertificatePJ() {
        return icpBRCertificatePJ;
    }

    /**
     *
     * @return boolean
     */
    public boolean isCertificateEquipment() {
        return icpBRCertificateEquipment != null;
    }

    /**
     *
     * @return Object ICPBRCertificateEquipment
     * @see
     * br.gov.frameworkdemoiselle.certificate.extension.serpro.security.certificate.extension.ICPBRCertificateEquipment
     */
    public ICPBRCertificateEquipment getICPBRCertificateEquipment() {
        return icpBRCertificateEquipment;
    }

    /**
     *
     * @return String
     */
    public String getEmail() {
        return email;
    }

}
