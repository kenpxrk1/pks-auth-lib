package ru.mirea.auth.lib.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Component
public class AuthenticationExceptionSupplier implements AuthenticationEntryPoint {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationExceptionSupplier.class);

    private final HandlerExceptionResolver resolver;

    public AuthenticationExceptionSupplier(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) {
        log.warn("Authentication failed for request [{} {}]: {}", request.getMethod(), request.getRequestURI(),
                authException.getMessage(), authException);
        resolver.resolveException(request, response, null, authException);
    }
}
