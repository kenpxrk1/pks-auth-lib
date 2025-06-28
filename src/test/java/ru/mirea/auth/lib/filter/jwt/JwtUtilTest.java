package ru.mirea.auth.lib.filter.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.mirea.auth.lib.exception.JwtValidationException;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class JwtUtilTest {
    private final JwtUtil jwtUtil = new JwtUtil();
    private final String secretKey = "24fff90104910fjweofnlwe812048091ukpeowfwp1313123123";
    private final String testUsername = "testUser";
    private final String testRole = "admin";

    // установка secretKey в jwtUtil через рефлексию
    @BeforeEach
    public void setUp() throws Exception {
        Field secretKeyField = JwtUtil.class.getDeclaredField("secretKey");
        secretKeyField.setAccessible(true);
        secretKeyField.set(jwtUtil, secretKey);
    }

    // извлечение юзернейма и проверка на совпадение с изначальным
    @Test
    void extractUsername_validUsername(){
        String token = Jwts.builder()
                .subject(testUsername)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        String extractedUsername = jwtUtil.extractUsername(token);

        assertEquals(testUsername, extractedUsername);
    }

    // извлечение роли и проверка на совпадение с изначальной
    @Test
    void extractRole_validRole(){
        String token = Jwts.builder()
                .claim("role", testRole)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        String extractedRole = jwtUtil.extractRole(token);

        assertEquals(testRole, extractedRole);
    }

    // проверка токена на валидность, если валиден исключение не выбрасывается
    @Test
    void validateToken_validToken(){
        String token = Jwts.builder()
                .subject(testUsername)
                .claim("role", testRole)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();

        Assertions.assertDoesNotThrow(()->jwtUtil.validateTokenOrThrow(token));
    }

    // проверка токена на валидность, если истек срок выбрасывается исключение JwtValidationException
    // с сообщением Expired JWT token
    @Test
    void validateToken_expiredToken(){
        Date expDate = Date.from(Instant.now());
        String token = Jwts.builder()
                .subject(testUsername)
                .claim("role", testRole)
                .expiration(expDate)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();

        JwtValidationException exception =
                Assertions.assertThrows(JwtValidationException.class, ()->jwtUtil.validateTokenOrThrow(token));
        assertEquals("Expired JWT token", exception.getMessage());
    }

    // проверка токена на валидность, если неправильно сформирован выбрасывается исключение JwtValidationException
    // с сообщением Malformed JWT token
    @Test
    void validateToken_malformedToken(){
        String token = "thats.invalid.token";

        JwtValidationException exception = Assertions.assertThrows(JwtValidationException.class,
                () -> jwtUtil.validateTokenOrThrow(token));
        assertEquals("Malformed JWT token", exception.getMessage());
    }

    // проверка токена на валидность, если неправильная подпись выбрасывается исключение JwtValidationException
    // с сообщением Invalid JWT token signature
    @Test
    void validateToken_invalidSignature(){
        String validToken = Jwts.builder()
                .subject(testUsername)
                .claim("role", testRole)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        String invalidToken = validToken + "14124q";

        JwtValidationException exception = Assertions.assertThrows(JwtValidationException.class,
                () -> jwtUtil.validateTokenOrThrow(invalidToken));
        assertEquals("Invalid JWT token signature", exception.getMessage());
    }

    // проверка токена на валидность, если secret key котороым был закодирован ключ не равен secret key
    // в методе выбрасывается исключение JwtValidationException с сообщением Invalid JWT token signature
    @Test
    void validateToken_invalidKey() throws IllegalAccessException, NoSuchFieldException {
        String validToken = Jwts.builder()
                .subject(testUsername)
                .claim("role", testRole)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();

        Field secretKeyField = JwtUtil.class.getDeclaredField("secretKey");
        secretKeyField.setAccessible(true);
        secretKeyField.set(jwtUtil, "fwefnmwkenflwenflewlfnlkewnflk");

        JwtValidationException exception = Assertions.assertThrows(JwtValidationException.class,
                () -> jwtUtil.validateTokenOrThrow(validToken));
        assertEquals("Invalid JWT token key", exception.getMessage());
    }
}
