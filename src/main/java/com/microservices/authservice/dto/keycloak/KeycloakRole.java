package com.microservices.authservice.dto.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeycloakRole {
    private String id;
    private String name;
    
    @JsonProperty("clientRole")
    private Boolean clientRole;
    
    private String description;
    
    @JsonProperty("composite")
    private Boolean composite;
}

