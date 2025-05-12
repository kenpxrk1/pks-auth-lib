package fast.delivery.auth.lib.dto;

import java.time.OffsetDateTime;

public record ErrorResponseDto(String message, OffsetDateTime timestamp) {
    public ErrorResponseDto(String message) {
        this(message, OffsetDateTime.now());
    }
}
