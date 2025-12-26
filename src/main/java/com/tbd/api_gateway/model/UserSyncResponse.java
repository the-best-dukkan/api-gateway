package com.tbd.api_gateway.model;

import java.util.Set;

public record UserSyncResponse(
        String email,
        String sub,
        String fullName,
        boolean profileComplete,
        Set<TbdRole>roles
) {
}
