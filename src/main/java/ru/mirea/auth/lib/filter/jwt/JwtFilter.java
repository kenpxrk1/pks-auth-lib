package ru.mirea.auth.lib.filter.jwt;

import ru.mirea.auth.lib.exception.JwtValidationException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
public class JwtFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);


    private final JwtUtil jwtUtil;
    private final HandlerExceptionResolver resolver;

    public JwtFilter(JwtUtil jwtUtil, @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.jwtUtil = jwtUtil;
        this.resolver = resolver;
    }

    /**
     * Filters incoming requests to authenticate users based on JWT tokens.
     *
     * @param request     the HTTP request
     * @param response    the HTTP response
     * @param filterChain the filter chain
     * @throws ServletException if an error occurs during filtering
     * @throws IOException      if an I/O error occurs during filtering
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (shouldSkipFilter(request)) {
            log.info("Skipping JWT filter for URI: {} in Thread: {}", request.getRequestURI(), Thread.currentThread().getName());
            filterChain.doFilter(request, response);
            return;
        }

        if (request.getHeader(AUTHORIZATION_HEADER) != null
                && request.getHeader(AUTHORIZATION_HEADER).startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = request.getHeader(AUTHORIZATION_HEADER).substring(7);
            try {
                jwtUtil.validateTokenOrThrow(token);
                setAuthentication(token, request);
                filterChain.doFilter(request, response);
            } catch (JwtValidationException e) {
                resolver.resolveException(request, response, null, e);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Sets the authentication for the current request.
     *
     * @param token the authentication token
     * @param request  the HTTP request
     */
    private void setAuthentication(String token, HttpServletRequest request) {
        String login = Optional.ofNullable(jwtUtil.extractUsername(token))
                .orElseThrow(() -> new JwtValidationException("Missing login in token",
                        new JwtException("Missing login (subject) in token")));

        String role = Optional.ofNullable(jwtUtil.extractRole(token))
                .orElseThrow(() -> new JwtValidationException("Missing role in token",
                        new JwtException("Missing role in token")));

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        login,
                        null,
                        Collections.singleton(new SimpleGrantedAuthority(role)));

        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    /**
     * Determines whether the filter should be skipped for the given request.
     *
     * @param request the HTTP request
     * @return true if the filter should be skipped, false otherwise
     */

    protected boolean shouldSkipFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith("/swagger-ui/") ||
                requestURI.startsWith("/v3/api-docs/") ||
                requestURI.startsWith("/v1/internal/") ||
                shouldSkipFilterAddons(requestURI);
    }

    /**
     * Additional conditions to determine whether the filter should be skipped.
     *
     * @param requestURI the request URI
     * @return true if the filter should be skipped, false otherwise
     */

    protected boolean shouldSkipFilterAddons(String requestURI) {
        return false; // Override in subclass if needed
    }
}
