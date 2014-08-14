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

    granted(0, "O token de carimbo de tempo está presente, conforme solicitado."),
    grantedWithMods(1, "O token de carimbo de tempo está presente com modificações."),
    rejection(2, "O token de carimbo de tempo foi rejeitado."),
    waiting(3, "O token de carimbo de tempo está aguardando."),
    revocationWarning(4, "A revogação de tempo ocorrerá em breve."),
    revocationNotification(5, "A revogação de tempo ocorreu."),
    unknownPKIStatus(6, "O status retornado é desconhecido.");

    private final int id;
    private final String message;

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
