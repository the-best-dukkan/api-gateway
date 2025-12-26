package com.tbd.api_gateway.model;

import java.util.Set;

public record UserSyncRequest(
        String email,
        String sub,
        String fullName,
        String picture,
        Boolean isEmailVerified
) {
}
