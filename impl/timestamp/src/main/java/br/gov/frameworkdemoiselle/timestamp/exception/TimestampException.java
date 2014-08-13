package br.gov.frameworkdemoiselle.timestamp.exception;

/**
 *
 * @author 07721825741
 */
public class TimestampException extends Exception {

    public TimestampException() {
    }

    public TimestampException(String message) {
        super(message);
    }

    public TimestampException(String message, Throwable cause) {
        super(message, cause);
    }
}
