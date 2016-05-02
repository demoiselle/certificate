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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Classe Generica   para   tratamento   de   atributos   de  alguns   atributos
 * de Pessoa  Fisica, Pessoa Juridica   e   Equipamento   de   acordo   com os
 * padroes definidos no DOC­ICP­04 pela ICP­BRASIL
 *
 * @author Humberto Pacheco - SERVICO FEDERAL DE PROCESSAMENTO DE DADOS
 */
public class OIDGeneric {

    private static final Logger LOGGER = Logger.getLogger(OIDGeneric.class.getName());

    /**
     * Instance for object.
     *
     * @param data -> byte array with certificate content.
     * @return Object GenericOID
     * @throws IOException
     * @throws Exception
     */
    public static OIDGeneric getInstance(byte[] data) throws IOException, Exception {
        ASN1InputStream is = new ASN1InputStream(data);
        DERSequence sequence = (DERSequence) is.readObject();
        DERObjectIdentifier objectIdentifier = (DERObjectIdentifier) sequence.getObjectAt(0);
        DERTaggedObject tag = (DERTaggedObject) sequence.getObjectAt(1);
        DEROctetString octetString = null;
        DERPrintableString printableString = null;
        DERUTF8String utf8String = null;
        DERIA5String ia5String = null;

        try {
            octetString = (DEROctetString) DEROctetString.getInstance(tag);
        } catch (Exception ex) {
            try {
                printableString = DERPrintableString.getInstance(tag);
            } catch (Exception e1) {
                try {
                    utf8String = DERUTF8String.getInstance(tag);
                } catch (Exception e2) {
                    ia5String = DERIA5String.getInstance(tag);
                }
            }
        }

        String className = "br.gov.frameworkdemoiselle.certificate.oid.OID_" + objectIdentifier.getId().replaceAll("[.]", "_");
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

        oidGenerico.setOid(objectIdentifier.getId());

        if (octetString != null) {
            oidGenerico.setData(new String(octetString.getOctets()));
        } else if (printableString != null) {
            oidGenerico.setData(printableString.getString());
        } else if (utf8String != null) {
            oidGenerico.setData(utf8String.getString());
        } else {
            oidGenerico.setData(ia5String.getString());
        }
        oidGenerico.initialize();
        return oidGenerico;
    }

    private String oid = null;
    private String data = null;
    protected Map<String, String> properties = new HashMap<String, String>();

    protected void initialize() {
        // Inicializa as propriedades do conteudo DATA
    }

    /**
     *
     * @param fields Campos do certificado
     */
    protected void initialize(Object[] fields) {
        int tmp = 0;

        for (int i = 0; i < fields.length; i += 2) {
            String key = (String) fields[i];
            int size = ((Number) fields[i + 1]).intValue();
            properties.put(key, data.substring(tmp, Math.min(tmp + size, data.length())));
            tmp += size;
        }
    }

    /**
     * Retorna o OID
     *
     * @return
     */
    public String getOid() {
        return oid;
    }

    /**
     * Retorna o conteudo de um OID
     *
     * @return
     */
    public String getData() {
        return data;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public void setData(String data) {
        this.data = data;
    }

}
