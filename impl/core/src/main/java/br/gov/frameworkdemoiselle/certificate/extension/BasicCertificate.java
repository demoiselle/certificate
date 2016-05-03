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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extensions;

/**
 * Basic Information for ICP-BRASIL (DOC-ICP-04) Certificates. Abstracts the
 * rules to PESSOA FISICA, PESSOA JURIDICA and EQUIPAMENTO/APLICAÇÃO
 *
 *
 * @author CETEC/CTCTA
 */
public class BasicCertificate {

    private static final Logger LOGGER = Logger.getLogger(BasicCertificate.class.getName());

    public static final String OID_A1_CERTIFICATE = "2.16.76.1.2.1";
    public static final String OID_A2_CERTIFICATE = "2.16.76.1.2.2";
    public static final String OID_A3_CERTIFICATE = "2.16.76.1.2.3";
    public static final String OID_A4_CERTIFICATE = "2.16.76.1.2.4";
    public static final String OID_S1_CERTIFICATE = "2.16.76.1.2.101";
    public static final String OID_S2_CERTIFICATE = "2.16.76.1.2.102";
    public static final String OID_S3_CERTIFICATE = "2.16.76.1.2.103";
    public static final String OID_S4_CERTIFICATE = "2.16.76.1.2.104";

    private X509Certificate certificate = null;
    private ICPBRSubjectAlternativeNames subjectAlternativeNames = null;
    private ICPBRKeyUsage keyUsage = null;
    private ICPBR_DN certificateFrom = null;
    private ICPBR_DN certificateFor = null;

    /**
     * @param certificate -> type X509Certificate
     * @see java.security.cert.X509Certificate
     */
    public BasicCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     *
     * @param data
     * @throws Exception
     */
    public BasicCertificate(byte[] data) throws Exception {
        this.certificate = getCertificate(data);
    }

    /**
     *
     * @param is
     * @throws Exception
     * @throws IOException
     */
    public BasicCertificate(InputStream is) throws IOException, Exception {
        this.certificate = getCertificate(is);
    }

    /**
     *
     * @param is -> InputStream
     * @return X509Certificate
     * @throws CertificateException
     * @throws IOException
     * @throws Exception
     */
    private X509Certificate getCertificate(InputStream is) throws CertificateException, IOException, Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        return cert;
    }

    /**
     *
     * @param data -> byte array
     * @return String
     */
    private String toString(byte[] data) {
        if (data == null) {
            return null;
        }
        return toString(new BigInteger(1, data));
    }

    /**
     *
     * @param bi -> Big Integer
     * @return String
     */
    private String toString(BigInteger bi) {
        if (bi == null) {
            return null;
        }

        String ret = bi.toString(16);

        if (ret.length() % 2 == 1) {
            ret = "0" + ret;
        }

        return ret.toUpperCase();
    }

    /**
     *
     * @param data -> Byte Array
     * @return X509Certificate
     * @throws Exception
     */
    private X509Certificate getCertificate(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        X509Certificate cert = getCertificate(bis);
        bis.close();
        bis = null;

        return cert;
    }

    /**
     * Return the certificate on original format X509Certificate<br>
     *
     * @return X509Certificate
     */
    public X509Certificate getX509Certificate() {
        return certificate;
    }

    /**
     * Returns the IssuerDn of certificate on ICPBR_DN format thats works as a
     * properties<br>
     *
     * The toString Method of this class returns IssuerDn.getName()<br>
     *
     * @return ICPBR_DN
     * @see ICPBR_DN
     * @throws IOException
     */
    public ICPBR_DN getCertificateIssuerDN() throws IOException {
        if (certificateFrom == null) {
            certificateFrom = new ICPBR_DN(certificate.getIssuerDN().getName());
        }
        return certificateFrom;
    }

    /**
     * Returns the SerialNumber of certificate on String format<br>
     *
     * @return String
     */
    public String getSerialNumber() {
        return toString(certificate.getSerialNumber());
    }

    /**
     * Returns the SubjectDN of certificate on ICPBR_DN on ICPBR_DN format thats
     * works as a properties<br>
     *
     * The toString Method of this class returns SubjectDN.getName()<br>
     *
     * @return ICPBR_DN
     * @see ICPBR_DN
     * @throws IOException
     */
    public ICPBR_DN getCertificateSubjectDN() throws IOException {
        if (certificateFor == null) {
            certificateFor = new ICPBR_DN(certificate.getSubjectDN().getName());
        }
        return certificateFor;
    }

    /**
     * Returns the name that was defined on CN for CertificateSubjectDN.<br>
     * Its similar to CertificateSubjectDN.getProperty("CN"), but ignoring<br>
     * the information after ":".<br>
     *
     * @return String
     */
    public String getNome() {
        try {
            String nome = this.getCertificateSubjectDN().getProperty("CN");
            int pos;

            pos = nome.indexOf(':');
            if (pos > 0) {
                return nome.substring(0, pos);
            }
            return nome;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @return Date -> Validate starts date
     */
    public Date getBeforeDate() {
        return certificate.getNotBefore();
    }

    /**
     *
     * @return Date -> Validate ends date
     */
    public Date getAfterDate() {
        return certificate.getNotAfter();
    }

    /**
     * Returns the ICPBRKeyUsage Object with the informations about uses of the
     * certificate<br>
     *
     * @return ICPBRKeyUsage
     * @see ICPBRKeyUsage
     */
    public ICPBRKeyUsage getICPBRKeyUsage() {
        if (keyUsage == null) {
            keyUsage = new ICPBRKeyUsage(certificate);
        }
        return keyUsage;
    }

    /**
     * Returns the SubjectAlternativeNames of certificate in<br>
     * ICPBRSubjectAlternativeNames format.<br>
     * If not exists, returns <b>null</b>.<br>
     *
     * @return ICPBRSubjectAlternativeNames
     * @see ICPBRSubjectAlternativeNames
     */
    public ICPBRSubjectAlternativeNames getICPBRSubjectAlternativeNames() {
        if (this.subjectAlternativeNames == null) {
            this.subjectAlternativeNames = new ICPBRSubjectAlternativeNames(this.certificate);
        }
        return this.subjectAlternativeNames;
    }

    /**
     * Returns the email address that was defined on
     * SubjectAlternativeNames.<br>
     * Similar getICPBRSubjectAlternativeNames().getEmail()<br>
     * If not exists, returns <b>null</b>.<br>
     *
     * @return String
     */
    public String getEmail() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getEmail();
    }

    /**
     * Check if the certificate has a "ICP-BRASIL Pessoa Fisica Certificate".
     * DOC-ICP-04<br>
     *
     * @return boolean
     */
    public boolean hasCertificatePF() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return false;
        }
        return getICPBRSubjectAlternativeNames().isCertificatePF();
    }

    /**
     * Returns data of "Pessoa Fisica" on certificate in ICPBRCertificatePF
     * format<br>
     * If its not a "Pessoa Fisica" certificate <br>
     * Returns o valor <b>null</b>
     *
     * @return ICPBRCertificatePF
     * @see ICPBRCertificatePF
     */
    public ICPBRCertificatePF getICPBRCertificatePF() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getICPBRCertificatePF();
    }

    /**
     * * Check if the certificate has a "ICP-BRASIL Pessoa Juridica
     * Certificate". DOC-ICP-04<br>
     *
     * @return boolean
     */
    public boolean hasCertificatePJ() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return false;
        }
        return getICPBRSubjectAlternativeNames().isCertificatePJ();
    }

    /**
     * Returns data of "Pessoa Juridica" on certificate in ICPBRCertificatePJ
     * format<br>
     * If its not a "Pessoa Juridica" certificate <br>
     * Returns o valor <b>null</b>
     *
     *
     * @return ICPBRCertificatePJ
     * @see ICPBRCertificatePJ
     */
    public ICPBRCertificatePJ getICPBRCertificatePJ() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getICPBRCertificatePJ();
    }

    /**
     * Check if the certificate has a "ICP-BRASIL Equipment (Equipamento ou
     * Aplicação) Certificate". DOC-ICP-04<br>
     *
     * @return boolean
     */
    public boolean hasCertificateEquipment() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return false;
        }
        return getICPBRSubjectAlternativeNames().isCertificateEquipment();
    }

    /**
     * Returns data of "Equipamento/Aplicacao" on certificate in
     * ICPBRCertificateEquipment format<br>
     * If its not a "Equipamento/Aplicacao" certificate <br>
     * Returns o valor <b>null</b>
     *
     *
     * @return ICPBRCertificateEquipment
     * @see ICPBRCertificateEquipment
     */
    public ICPBRCertificateEquipment getICPBRCertificateEquipment() {
        if (getICPBRSubjectAlternativeNames() == null) {
            return null;
        }
        return getICPBRSubjectAlternativeNames().getICPBRCertificateEquipment();
    }

    /**
     * Returns the PathLength value of Certificate BasicConstraint.<br>
     * * <b>0</b> - if CA.<br>
     * * <b>1</b> - for End User Certificate.<br>
     *
     * @return int
     */
    public int getPathLength() {
        return certificate.getBasicConstraints();
    }

    /**
     * Check if is a Certificate Authority Certificate (ICP-BRASIL = AC).<br>
     * * <b>true</b> - If CA.<br>
     * * <b>false</b> -for End User Certificate.<br>
     *
     * @return boolean
     */
    public boolean isCertificadoAc() {
        return certificate.getBasicConstraints() >= 0;
    }

    /**
     * returns the ICP-BRASIL Level Certificate(A1, A2, A3, A4, S1, S2, S3,
     * S4).<br>
     * DOC-ICP-04 Returns the <b>null</b> value if the CertificatePolicies is
     * NOT present.
     *
     * @return String
     */
    public String getNivelCertificado() {
        try {
            DERSequence seq = (DERSequence) getExtensionValue(X509Extensions.CertificatePolicies.getId());
            if (seq == null) {
                return null;
            }
            for (int pos = 0; pos < seq.size(); pos++) {
                PolicyInformation policyInformation = new PolicyInformation((ASN1Sequence) seq.getObjectAt(pos));

                String id = policyInformation.getPolicyIdentifier().getId();
                if (id == null) {
                    continue;
                }

                if (id.startsWith(OID_A1_CERTIFICATE)) {
                    return "A1";
                }
                if (id.startsWith(OID_A2_CERTIFICATE)) {
                    return "A2";
                }
                if (id.startsWith(OID_A3_CERTIFICATE)) {
                    return "A3";
                }
                if (id.startsWith(OID_A4_CERTIFICATE)) {
                    return "A4";
                }
                if (id.startsWith(OID_S1_CERTIFICATE)) {
                    return "S1";
                }
                if (id.startsWith(OID_S2_CERTIFICATE)) {
                    return "S2";
                }
                if (id.startsWith(OID_S3_CERTIFICATE)) {
                    return "S3";
                }
                if (id.startsWith(OID_S4_CERTIFICATE)) {
                    return "S4";
                }
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Returns the AuthorityKeyIdentifier extension value on String format.<br>
     * Otherwise, returns <b>null</b>.<br>
     *
     * @return String
     * @throws IOException
     */
    public String getAuthorityKeyIdentifier() throws IOException {
        // TODO - Precisa validar este metodo com a RFC
        DERSequence seq = (DERSequence) getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
        if (seq == null || seq.size() == 0) {
            return null;
        }
        DERTaggedObject tag = (DERTaggedObject) seq.getObjectAt(0);
        DEROctetString oct = (DEROctetString) DEROctetString.getInstance(tag);

        return toString(oct.getOctets());
    }

    /**
     * Returns the SubjectKeyIdentifier extension value on String format.<br>
     * Otherwise, returns <b>null</b>.<br>
     *
     * @return String
     * @throws java.io.IOException
     */
    public String getSubjectKeyIdentifier() throws IOException {
        // TODO - Precisa validar este metodo com a RFC
        DEROctetString oct = (DEROctetString) getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
        if (oct == null) {
            return null;
        }

        return toString(oct.getOctets());
    }

    /**
     * Returns a List of URL for Certificate Revocation List. Must have on or
     * more<br>
     * Otherwise, returns <b>null</b>.<br>
     *
     * @return String
     * @throws IOException
     */
    public List<String> getCRLDistributionPoint() throws IOException {

        List<String> lcrS = new ArrayList<String>();
        DERObject derObj = getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (derObj == null) {
            return null;
        }
        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(derObj);
        DistributionPoint[] dp = crlDistPoint.getDistributionPoints();
        for (int i = 0; i < dp.length; i++) {
            DERSequence seq = (DERSequence) new ASN1InputStream(dp[i].getDistributionPoint().getName().getDEREncoded()).readObject();
            DERTaggedObject tag = (DERTaggedObject) seq.getObjectAt(0);
            try {
                ASN1OctetString oct = DEROctetString.getInstance(tag);
                lcrS.add(new String(oct.getOctets()));
            } catch (Exception e) {
                // Não é um objeto com informação de DistributionPoint
            }

        }
        return lcrS;
    }

    /**
     * Returns the DERObject for the informed OID<br>
     * atraves do OID.<br>
     *
     * @param oid
     * @return DERObject
     * @see DERObject
     */
    public DERObject getExtensionValue(String oid) {
        byte[] extvalue = certificate.getExtensionValue(oid);
        if (extvalue == null) {
            return null;
        }
        try {
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(extvalue).readObject());
            return (new ASN1InputStream(oct.getOctets()).readObject());
        } catch (IOException ex) {
            LOGGER.info(ex.getMessage());
        }
        return null;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        try {
            SimpleDateFormat dtValidade = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

            builder.append("\n");
            builder.append("-----------------------------------------\n");
            builder.append("Certificado de..........[").append(this.getCertificateIssuerDN()).append("]\n");
            builder.append("Serial Number...........[").append(this.getSerialNumber()).append("]\n");
            builder.append("Certificado para........[").append(this.getCertificateSubjectDN()).append("]\n");
            builder.append("Nome do Certif..........[").append(this.getNome()).append("]\n");
            builder.append("Validade................[").append(dtValidade.format(this.getBeforeDate())).append(" ate ").append(dtValidade.format(this.getAfterDate())).append("]\n");
            builder.append("Email...................[").append(this.getEmail()).append("]\n");
            builder.append("-----------------------------------------\n");
            builder.append("Tem dados PF............[").append(this.hasCertificatePF()).append("]\n");
            if (this.hasCertificatePF()) {
                ICPBRCertificatePF ippBRCertificatePF = this.getICPBRCertificatePF();
                builder.append("CPF.....................[").append(ippBRCertificatePF.getCPF()).append("]\n");
                builder.append("Data Nascimento.........[").append(ippBRCertificatePF.getDataNascimento()).append("]\n");
                builder.append("PIS.....................[").append(ippBRCertificatePF.getNis()).append("]\n");
                builder.append("RG......................[").append(ippBRCertificatePF.getRg()).append("]\n");
                builder.append("Orgão RG................[").append(ippBRCertificatePF.getOrgaoExpedidorRg()).append("]\n");
                builder.append("UF RG...................[").append(ippBRCertificatePF.getUfExpedidorRg()).append("]\n");
                builder.append("CEI.....................[").append(ippBRCertificatePF.getCEI()).append("]\n");
                builder.append("Titulo..................[").append(ippBRCertificatePF.getTituloEleitor()).append("]\n");
                builder.append("Seção...................[").append(ippBRCertificatePF.getSecaoTituloEleitor()).append("]\n");
                builder.append("Zona....................[").append(ippBRCertificatePF.getZonaTituloEleitor()).append("]\n");
                builder.append("Municipio Titulo........[").append(ippBRCertificatePF.getMunicipioTituloEleitor()).append("]\n");
                builder.append("UF Titulo...............[").append(ippBRCertificatePF.getUfTituloEleitor()).append("]\n");
            }

            builder.append("-----------------------------------------\n");
            builder.append("Tem dados PJ............[").append(this.hasCertificatePF()).append("]\n");
            if (this.hasCertificatePJ()) {
                ICPBRCertificatePJ tdPJ = this.getICPBRCertificatePJ();
                builder.append("CNPJ....................[").append(tdPJ.getCNPJ()).append("]\n");
                builder.append("CEI.....................[").append(tdPJ.getCEI()).append("]\n");
                builder.append("NIS.....................[").append(tdPJ.getNis()).append("]\n");
                builder.append("Responsável.............[").append(tdPJ.getNomeResponsavel()).append("]\n");
            }

            builder.append("-----------------------------------------\n");
            builder.append("Tem dados Equip.........:").append(this.hasCertificateEquipment()).append("]\n");
            if (this.hasCertificateEquipment()) {
                ICPBRCertificateEquipment tdEq = this.getICPBRCertificateEquipment();
                builder.append("CNPJ....................[").append(tdEq.getCNPJ()).append("]\n");
                builder.append("NIS.....................[").append(tdEq.getNis()).append("]\n");
                builder.append("Nome Empresa............[").append(tdEq.getNomeEmpresarial()).append("]\n");
                builder.append("Responsável.............[").append(tdEq.getNomeResponsavel()).append("]\n");
            }

            builder.append("-----------------------------------------\n");
            builder.append("Eh CertificadoAC........[").append(this.isCertificadoAc()).append("]\n");
            builder.append("PathLength..............[").append(this.getPathLength()).append("]\n");
            builder.append("Tipo Certificado........[").append(this.getNivelCertificado()).append("]\n");
            builder.append("Tipo de Uso.............[").append(this.getICPBRKeyUsage()).append("]\n");

            builder.append("-----------------------------------------\n");
            builder.append("Authority KeyID.........[").append(this.getAuthorityKeyIdentifier()).append("]\n");
            builder.append("Subject KeyID...........[").append(this.getSubjectKeyIdentifier()).append("]\n");
            builder.append("CRL DistPoint...........[").append(this.getCRLDistributionPoint()).append("]\n");
        } catch (IOException ex) {
            LOGGER.info(ex.getMessage());
        }

        return builder.toString();
    }

}
