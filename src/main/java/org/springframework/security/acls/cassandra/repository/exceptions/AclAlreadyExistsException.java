package org.springframework.security.acls.cassandra.repository.exceptions;

public class AclAlreadyExistsException extends RuntimeException {

	private static final long serialVersionUID = 1891804328079992377L;

	public AclAlreadyExistsException() {
	}

	public AclAlreadyExistsException(String message) {
		super(message);
	}

	public AclAlreadyExistsException(Throwable cause) {
		super(cause);
	}

	public AclAlreadyExistsException(String message, Throwable cause) {
		super(message, cause);
	}

	public AclAlreadyExistsException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
