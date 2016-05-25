package br.gov.frameworkdemoiselle.certificate.ui.util;

public class AuthorizedException extends RuntimeException{
	private static final long serialVersionUID = 1L;


	/**
	 * Construtor recebendo mensagem e causa
	 * 
	 * @param message
	 * @param error
	 */
	public AuthorizedException(String message, Throwable error) {
		super(message, error);
	}

	
	/**
	 * Construtor recebendo mensagem
	 * 
	 * @param message
	 */
	public AuthorizedException(String message) {
		super(message);
	}


}
