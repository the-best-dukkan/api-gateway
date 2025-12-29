package com.tbd.api_gateway.model;

public record UserSyncRequest(
        String email,
        String sub,
        String fullName,
        String picture,
        Boolean isEmailVerified
) {
}
