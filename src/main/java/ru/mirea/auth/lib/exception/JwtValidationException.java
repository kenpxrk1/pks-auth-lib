package ru.mirea.auth.lib.exception;

public class JwtValidationException extends RuntimeException {
    public JwtValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
