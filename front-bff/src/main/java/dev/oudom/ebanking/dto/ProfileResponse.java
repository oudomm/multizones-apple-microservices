package dev.oudom.ebanking.dto;

import lombok.Builder;

@Builder
public record ProfileResponse(
        boolean isAuthenticated,
        String uuid,
        String username,
        String fullName,
        String email,
        String phoneNumber,
        String gender,
        String birthdate,
        String picture,
        String coverImage,
        Object roles
) {}
