package com.pickfolio.auth.exception;

public class UsernameAlreadyExistsException extends RuntimeException {
    public UsernameAlreadyExistsException() {
        super("A user with this username already exists, please try again with a different username.");
    }

    public UsernameAlreadyExistsException(String username) {
        super("A user with the username '" + username + "' already exists, please try again with a different username.");
    }

    public UsernameAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}