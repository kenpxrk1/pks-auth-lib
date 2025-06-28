package ru.mirea.auth.lib.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.mirea.auth.lib.filter.jwt.JwtUtil;

import java.time.Instant;
import java.util.Date;

@ExtendWith(MockitoExtension.class)
public abstract class AbstractInitialization{
    protected static JwtUtil jwtUtil;
    protected static String testUsername;
    protected static String testRole;
    protected static String secretKey;
    protected static String validToken;
    protected static String expiredToken;
    protected static String malformedToken;
    protected static String invalidSignatureToken;

    @BeforeAll
    public static void init(){
        jwtUtil = new JwtUtil();
        testUsername = "userName";
        testRole = "admin";
        secretKey = "ewkmndflkewn203e1j1oi39012301023ijweiod1jm20idj1ioiod1";
        validToken = Jwts.builder()
                .subject(testUsername)
                .claim("role", testRole)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        expiredToken = Jwts.builder()
                .subject(testUsername)
                .claim("role", testRole)
                .expiration( Date.from(Instant.now()) )
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        malformedToken = "thats.invalid.token";
        invalidSignatureToken = validToken + "14124q";

    }
}