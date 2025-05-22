package ru.mirea.auth.lib.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Component
public class AccessDeniedExceptionSupplier implements AccessDeniedHandler {
    private static final Logger log = LoggerFactory.getLogger(AccessDeniedExceptionSupplier.class);

    private final HandlerExceptionResolver resolver;

    public AccessDeniedExceptionSupplier(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) {
        log.warn("Authentication failed for request [{} {}]: {}", request.getMethod(), request.getRequestURI(),
                accessDeniedException.getMessage(), accessDeniedException);
        resolver.resolveException(request, response, null, accessDeniedException);
    }
}
