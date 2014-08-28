/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.certificate.signer.pkcs7.attribute;

import br.gov.frameworkdemoiselle.certificate.signer.SignerException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 *
 * @author 07721825741
 */
public interface TimeStampGenerator {

    void initialize(byte[] content, PrivateKey privateKey, Certificate[] certificates);

    byte[] generateTimeStamp() throws SignerException;

    void validateTimeStamp(byte[] response) throws SignerException;

}
