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

/**
 *
 * Classe Generica   para   tratamento   de   atributos   de  alguns   atributos
 *   de   Pessoa  Fisica, Pessoa Juridica   e   Equipamento   de   acordo   com
 *   os   padroes  definidos   no  DOC­ICP­04 v2.0 de
 * 18/04/2006, pela ICP­BRASIL
 *
 */
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;

import sun.security.util.DerValue;
import sun.security.x509.OtherName;

@SuppressWarnings("restriction")
public class OIDGeneric {

    private String oid = null;
    private String data = null;
    protected Map<String, String> properties = new HashMap<String, String>();
	private static ASN1InputStream is;

    protected OIDGeneric() {
    }

    /**
     * Instance for object.
     *
     * @param data Conjunto de bytes com o conteúdo do certificado
     * @return Object GenericOID
     * @throws IOException Retorna a exceção IOException
     * @throws Exception Retorna a exceção Exception
     */
    public static OIDGeneric getInstance(byte[] data) throws IOException, Exception {
        is = new ASN1InputStream(data);
        DLSequence sequence = (DLSequence) is.readObject();
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
        DERTaggedObject taggedObject = (DERTaggedObject) sequence.getObjectAt(1);
        DERTaggedObject taggedObject2 = (DERTaggedObject) taggedObject.getObject();

        DEROctetString octet = null;
        DERPrintableString print = null;
        DERUTF8String utf8 = null;
        DERIA5String ia5 = null;

        try {
            octet = (DEROctetString) taggedObject2.getObject();
        } catch (Exception e) {
            try {
                print = (DERPrintableString) taggedObject2.getObject();
            } catch (Exception e1) {
                try {
                    utf8 = (DERUTF8String) taggedObject2.getObject();
                } catch (Exception e2) {
                    ia5 = (DERIA5String) taggedObject2.getObject();
                }
            }
        }

        String className = "br.gov.frameworkdemoiselle.certificate.oid.OID_" + oid.getId().replaceAll("[.]", "_");
        OIDGeneric oidGenerico;
        try {
            oidGenerico = (OIDGeneric) Class.forName(className).newInstance();
        } catch (InstantiationException e) {
            throw new Exception("Can not instace class '" + className + "'.", e);
        } catch (IllegalAccessException e) {
            throw new Exception("Was not possible instace class '" + className + "'.", e);
        } catch (ClassNotFoundException e) {
            oidGenerico = new OIDGeneric();
        }

        oidGenerico.oid = oid.getId();

        if (octet != null) {
            oidGenerico.data = new String(octet.getOctets());
        } else {
            if (print != null) {
                oidGenerico.data = print.getString();
            } else {
                if (utf8 != null) {
                    oidGenerico.data = utf8.getString();
                } else {
                    oidGenerico.data = ia5.getString();
                }
            }
        }

        oidGenerico.initialize();

        return oidGenerico;
    }

    /**
     *
     * @param der Certificate DER (sun.security.util.DerValue)
     * @return OIDGenerico
     * @throws IOException Retorna a exceção IOException
     * @throws Exception Retorna a exceção Exception
     */
    public static OIDGeneric getInstance(DerValue der) throws IOException, Exception {
        OtherName on = new OtherName(der);
        String className = "br.gov.frameworkdemoiselle.certificate.oid.OID_" + on.getOID().toString().replaceAll("[.]", "_");

        OIDGeneric oidGenerico;
        try {
            oidGenerico = (OIDGeneric) Class.forName(className).newInstance();
        } catch (InstantiationException e) {
            throw new Exception("Was not possible instance class '" + className + "'.", e);
        } catch (IllegalAccessException e) {
            throw new Exception("Was not possible instance class '" + className + "'.", e);
        } catch (ClassNotFoundException e) {
            oidGenerico = new OIDGeneric();
        }

        oidGenerico.oid = on.getOID().toString();
        oidGenerico.data = new String(on.getNameValue()).substring(6);
        oidGenerico.initialize();

        return oidGenerico;
    }

    protected void initialize() {
        // Inicializa as propriedades do conteudo DATA
    }

    /**
     *
     * @param fields Campos do certificado
     */
    protected void initialize(Object[] fields) {
        //TODO fazer alteracao para contemplar o novo tamanho de campo do RG

        int tmp = 0;

        for (int i = 0; i < fields.length; i += 2) {
            String key = (String) fields[i];
            int size = ((Integer) fields[i + 1]);
            properties.put(key, data.substring(tmp, Math.min(tmp + size, data.length())));
            tmp += size;
        }
    }

    /**
     *
     * @return set of OID on String format
     */
    public String getOid() {
        return oid;
    }

    /**
     *
     * @return content on String format
     */
    public String getData() {
        return data;
    }
}
