package dev.oudom.ebanking.controller;

import dev.oudom.ebanking.dto.AuthenticationResponse;
import dev.oudom.ebanking.dto.ProfileResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @GetMapping("/me")
    public ProfileResponse me(@AuthenticationPrincipal org.springframework.security.oauth2.core.oidc.user.OidcUser user) {

        if (user == null) {
            return ProfileResponse.builder()
                    .isAuthenticated(false)
                    .build();
        }

        var c = user.getClaims();

        return ProfileResponse.builder()
                .isAuthenticated(true)
                .uuid((String) c.get("uuid"))
                .username((String) c.getOrDefault("username", user.getPreferredUsername()))
                .fullName((String) c.getOrDefault("full_name", c.get("name")))
                .email((String) c.get("email"))
                .phoneNumber((String) c.get("phone_number"))
                .gender((String) c.get("gender"))
                .birthdate((String) c.get("birthdate"))
                .picture((String) c.get("picture"))
                .coverImage((String) c.get("cover_image"))
                .roles(c.get("roles"))
                .build();
    }


    @GetMapping("/is-authenticated")
    public AuthenticationResponse isAuthenticated(Authentication authentication) {
        return AuthenticationResponse.builder()
                .isAuthenticated(authentication != null)
                .build();
    }
}
