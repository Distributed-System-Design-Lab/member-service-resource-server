package com.distributed_system_design_lab.member_service_resource_server.controller;

import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.distributed_system_design_lab.member_service_resource_server.entity.Keycloak;
import com.distributed_system_design_lab.member_service_resource_server.service.KeycloakService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/keycloak")
public class KeycloakController {

    private static final Logger log = LoggerFactory.getLogger(KeycloakController.class);

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private KeycloakService keycloakService;

    @GetMapping("/redirect")
    public void keycloakRedirect(@RequestParam("code") String code, HttpServletResponse response) throws IOException {
        String clientId = "peoplesystem";
        String redirectUri = "http://localhost:8081/resource-server/keycloak/redirect";
        String clientSecret = "7YQeh5Rfd73E5tliixooqDXJyn5Dhpet";
        String tokenUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token";

        try {
            // 創建 JWT
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(tokenUrl)
                    .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                    .jwtID(UUID.randomUUID().toString())
                    .build();
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            // 使用 client secret 簽名 JWT
            JWSSigner signer = new MACSigner(clientSecret);
            signedJWT.sign(signer);

            String clientAssertion = signedJWT.serialize();

            // 請求 Keycloak 的訪問令牌
            MultiValueMap<String, String> tokenParams = new LinkedMultiValueMap<>();
            tokenParams.add("client_id", clientId);
            tokenParams.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            tokenParams.add("client_assertion", clientAssertion);
            tokenParams.add("code", code);
            tokenParams.add("grant_type", "authorization_code");
            tokenParams.add("redirect_uri", redirectUri);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(tokenParams, headers);

            ResponseEntity<Map> tokenResponse = restTemplate.exchange(tokenUrl, HttpMethod.POST, entity, Map.class);
            String accessToken = (String) tokenResponse.getBody().get("access_token");

            // Ensure the code is used only once
            if (accessToken == null) {
                throw new RuntimeException("Failed to obtain access token");
            }

            // Request user info from Keycloak
            String userInfoUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/userinfo";
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.set("Authorization", "Bearer " + accessToken);
            HttpEntity<String> userEntity = new HttpEntity<>(userHeaders);

            ResponseEntity<Map> userResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userEntity,
                    Map.class);
            Map<String, Object> userInfo = userResponse.getBody();

            // Log Keycloak user info
            log.info("Keycloak User Info: {}", userInfo);

            // Extract user info
            String username = (String) userInfo.get("preferred_username");
            String email = (String) userInfo.get("email");

            // Redirect back to frontend with user info and token
            response.sendRedirect(
                    "http://localhost:3000/" + "?username=" + username + "&email=" + email + "&token=" + accessToken);
        } catch (Exception e) {
            log.error("Error processing OAuth redirect", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing OAuth redirect");
        }
    }

    // Logout API to revoke tokens
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestParam String accessToken, @RequestParam String refreshToken) {
        String logoutUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/logout";
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            restTemplate.exchange(logoutUrl, HttpMethod.POST, request, String.class);
            return ResponseEntity.ok("Logged out successfully");
        } catch (Exception e) {
            log.error("Logout failed", e);
            return ResponseEntity.status(500).body("Logout failed");
        }
    }

    // API to fetch user information by username or email
    // API to fetch user information by username or email
    @GetMapping("/findUserInfo")
    public ResponseEntity<?> findUserInfo(@RequestParam(required = false) String username,
            @RequestParam(required = false) String email) {
        if (username == null && email == null) {
            return ResponseEntity.badRequest().body("Either username or email must be provided.");
        }

        Optional<Keycloak> userInfo = Optional.empty();

        if (username != null) {
            Keycloak user = keycloakService.findByUsername(username);
            userInfo = Optional.ofNullable(user);
        } else if (email != null) {
            Keycloak user = keycloakService.findByEmail(email);
            userInfo = Optional.ofNullable(user);
        }

        if (userInfo.isEmpty()) {
            return ResponseEntity.status(404).body("User not found.");
        }

        return ResponseEntity.ok(userInfo.get());
    }

}
