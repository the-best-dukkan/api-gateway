package com.tbd.api_gateway.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenMetadata {

    private String sub;
    private String email;
    private Set<TbdRole> roles;
    private String jti;
    private Date expiration;
    private String tokenType;
}
