package ru.mirea.auth.lib.filter.jwt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.mirea.auth.lib.exception.JwtValidationException;
import ru.mirea.auth.lib.filter.AbstractInitialization;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class JwtUtilTest extends AbstractInitialization {
    @BeforeEach
    void setUp() throws IllegalAccessException, NoSuchFieldException {
        Field secretKeyField = JwtUtil.class.getDeclaredField("secretKey");
        secretKeyField.setAccessible(true);
        secretKeyField.set(jwtUtil, secretKey);
    }

    @Test
    void extractUsername_validUsername(){
        String extractedUsername = jwtUtil.extractUsername(validToken);

        assertEquals(testUsername, extractedUsername);
    }

    @Test
    void extractRole_validRole(){
        String extractedRole = jwtUtil.extractRole(validToken);

        assertEquals(testRole, extractedRole);
    }

    @Test
    void validateToken_validToken(){
        Assertions.assertDoesNotThrow(()->jwtUtil.validateTokenOrThrow(validToken));
    }

    @Test
    void validateToken_expiredToken(){
        JwtValidationException exception =
                Assertions.assertThrows(JwtValidationException.class, ()->jwtUtil.validateTokenOrThrow(expiredToken));
        assertEquals("Expired JWT token", exception.getMessage());
    }

    @Test
    void validateToken_malformedToken(){
        JwtValidationException exception = Assertions.assertThrows(JwtValidationException.class,
                () -> jwtUtil.validateTokenOrThrow(malformedToken));
        assertEquals("Malformed JWT token", exception.getMessage());
    }

    @Test
    void validateToken_invalidSignature(){
        JwtValidationException exception = Assertions.assertThrows(JwtValidationException.class,
                () -> jwtUtil.validateTokenOrThrow(invalidSignatureToken));
        assertEquals("Invalid JWT token signature", exception.getMessage());
    }

    @Test
    void validateToken_invalidKey() throws IllegalAccessException, NoSuchFieldException {
        Field secretKeyField = JwtUtil.class.getDeclaredField("secretKey");
        secretKeyField.setAccessible(true);
        secretKeyField.set(jwtUtil, "fwefnmwkenflwenflewlfnlkewnflk");

        JwtValidationException exception = Assertions.assertThrows(JwtValidationException.class,
                () -> jwtUtil.validateTokenOrThrow(validToken));
        assertEquals("Invalid JWT token key", exception.getMessage());
    }
}
