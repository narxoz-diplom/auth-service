package com.microservices.authservice.dto;

import lombok.Data;

import java.util.List;

@Data
public class BulkUserResolveRequest {
    private List<String> userIds;
}
