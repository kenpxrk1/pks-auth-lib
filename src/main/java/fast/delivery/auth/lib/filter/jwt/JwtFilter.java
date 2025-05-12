package fast.delivery.auth.lib.filter.jwt;

import fast.delivery.auth.lib.exception.JwtValidationException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    private final JwtUtil jwtUtil;
    private final HandlerExceptionResolver resolver;

    public JwtFilter(JwtUtil jwtUtil, HandlerExceptionResolver resolver) {
        this.jwtUtil = jwtUtil;
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (request.getHeader(AUTHORIZATION_HEADER) != null
                && request.getHeader(AUTHORIZATION_HEADER).startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = request.getHeader(AUTHORIZATION_HEADER).substring(7);
            try {
                jwtUtil.validateTokenOrThrow(token);

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
                filterChain.doFilter(request, response);
            } catch (JwtValidationException e) {
                resolver.resolveException(request, response, null, e);
            }
        } else {
            filterChain.doFilter(request, response);
        }

    }
}
