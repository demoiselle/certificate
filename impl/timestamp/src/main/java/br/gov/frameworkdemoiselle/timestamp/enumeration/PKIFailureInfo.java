/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.enumeration;

/**
 *
 * @author 07721825741
 */
public enum PKIFailureInfo {

    badAlg(0, "Unrecognized or unsupported Algorithm Identifier."),
    badRequest(2, "Transaction not permitted or supported."),
    badDataFormat(5, "The data submitted has the wrong format."),
    timeNotAvailable(14, "The TSA’s time source is not available."),
    unacceptedPolicy(15, "The requested TSA policy is not supported by the TSA."),
    unacceptedExtension(16, "The requested extension is not supported by the TSA."),
    addInfoNotAvailable(17, "The additional information requested could not be understoodor is not available."),
    systemFailure(25, "The request cannot be handled due to system failure.");
    private int id;
    private String message;

    private PKIFailureInfo(int id, String message) {
        this.id = id;
        this.message = message;
    }

    public int getId() {
        return id;
    }

    public String getMessage() {
        return message;
    }
}
