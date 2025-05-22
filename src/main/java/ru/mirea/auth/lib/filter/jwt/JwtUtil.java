package ru.mirea.auth.lib.filter.jwt;

import ru.mirea.auth.lib.exception.JwtValidationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {

    @Value("${jwt.secret-key}")
    private String secretKey;

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    public void validateTokenOrThrow(String token) {
        try {
            Jwts
                    .parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            throw new JwtValidationException("Expired JWT token", e);
        } catch (MalformedJwtException e) {
            throw new JwtValidationException("Malformed JWT token", e);
        } catch (SignatureException e) {
            throw new JwtValidationException("Invalid JWT token signature", e);
        } catch (KeyException e) {
            throw new JwtValidationException("Invalid JWT token key", e);
        } catch (JwtException e) {
            throw new JwtValidationException(e.getMessage(), e);
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
}
