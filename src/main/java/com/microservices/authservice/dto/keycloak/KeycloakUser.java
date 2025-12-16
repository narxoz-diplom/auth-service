package com.microservices.authservice.dto.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeycloakUser {
    private String id;
    private String username;
    private String email;
    
    @JsonProperty("firstName")
    private String firstName;
    
    @JsonProperty("lastName")
    private String lastName;
    
    private Boolean enabled;
    
    @JsonProperty("emailVerified")
    private Boolean emailVerified;
    
    @JsonProperty("createdTimestamp")
    private Long createdTimestamp;
    
    private List<String> requiredActions;
    
    private Map<String, List<String>> attributes;
}

