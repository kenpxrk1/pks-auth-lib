package ru.mirea.auth.lib.exception;

import ru.mirea.auth.lib.dto.ErrorResponseDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Order(1)
public class AuthLibExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(AuthLibExceptionHandler.class);

    @ExceptionHandler(JwtValidationException.class)
    private ResponseEntity<ErrorResponseDto> handleException(JwtValidationException e) {
        ErrorResponseDto response = new ErrorResponseDto(e.getMessage());
        log.error("Jwt validation exception: {}", e.getMessage(), e);
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    private ResponseEntity<ErrorResponseDto> handleException(AccessDeniedException e) {
        ErrorResponseDto response = new ErrorResponseDto("Access denied");
        log.error("Access denied: {}", e.getMessage(), e);
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AuthenticationException.class)
    private ResponseEntity<ErrorResponseDto> handleException(AuthenticationException e) {
        ErrorResponseDto response = new ErrorResponseDto(e.getMessage());
        log.debug("Authentication exception: {}", e.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }
}
