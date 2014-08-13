/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.enumeration;

/**
 *
 * @author 07721825741
 */
public enum PKIStatus {

    granted(0, "Granted"),
    grantedWithMods(1, "Granted With Mods"),
    rejection(2, "Rejection"),
    waiting(3, "Waiting"),
    revocationWarning(4, "Revocation Warning"),
    revocationNotification(5, "Revocation Notification");
    private int id;
    private String message;

    private PKIStatus(int id, String message) {
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
