package org.springframework.security.acls.cassandra.repository.exceptions;

public class AclNotFoundException extends RuntimeException {

	private static final long serialVersionUID = 1891804328079992377L;

	public AclNotFoundException() {
	}

	public AclNotFoundException(String message) {
		super(message);
	}

	public AclNotFoundException(Throwable cause) {
		super(cause);
	}

	public AclNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	public AclNotFoundException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
