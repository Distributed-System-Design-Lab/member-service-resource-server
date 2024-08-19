package com.distributed_system_design_lab.member_service_resource_server.controller;

import java.io.IOException;
import java.time.Instant;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
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

    private String clientId = "peoplesystem";
    private String clientSecret = "7YQeh5Rfd73E5tliixooqDXJyn5Dhpet";

    @GetMapping("/redirect")
    public void keycloakRedirect(@RequestParam("code") String code, HttpServletResponse response) throws IOException {
        System.err.println(code);
        String redirectUri = "http://localhost:8081/resource-server/keycloak/redirect";

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
            String refreshToken = (String) tokenResponse.getBody().get("refresh_token");

            // Ensure the code is used only once
            if (accessToken == null || refreshToken == null) {
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
            keycloakService.deleteByUsername(username);

            // Create or update Keycloak user entity and save to database
            Keycloak user = new Keycloak();
            user.setUsername(username);
            user.setEmail((String) userInfo.get("email"));
            user.setGivenName((String) userInfo.get("given_name"));
            user.setFamilyName((String) userInfo.get("family_name"));
            user.setEmailVerified((Boolean) userInfo.get("email_verified"));
            user.setSub((String) userInfo.get("sub"));
            user.setAccessToken(accessToken);
            user.setRefreshToken(refreshToken);
            user.setIssuedAt(Instant.now());
            user.setExpiresIn(Instant.now().plusSeconds(3600));
            keycloakService.saveKeycloakData(user);

            log.info("User saved or updated in Keycloak table: {}", user);

            // Redirect back to frontend with user info and token
            response.sendRedirect(
                    "http://localhost:3000/" + "?username=" + username + "&email=" + user.getEmail() + "&token="
                            + accessToken);
        } catch (Exception e) {
            log.error("Error processing OAuth redirect", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing OAuth redirect");
        }
    }

    // Logout API to revoke tokens
    @CrossOrigin
    @PostMapping("/logout")
    public ResponseEntity<?> logout(Keycloak keycloak) {
        String logoutUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/logout";

        String refreshToken = keycloak.getRefreshToken();
        System.err.println("refreshToken" + refreshToken);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        try {
            restTemplate.exchange(logoutUrl, HttpMethod.POST, entity, String.class);
            keycloakService.deleteByUsername(keycloak.getUsername());
            return ResponseEntity.ok("Logout successful");
        } catch (Exception e) {
            log.error("Logout failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Logout failed");
        }
    }

    @GetMapping("/getUserInfo")
    public ResponseEntity<?> getUserInfo(@RequestParam("authorizationCode") String authorizationCode) {
        // Token 請求的 URL
        String tokenUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token";

        // 請求 Token
        try {
            MultiValueMap<String, String> bodyParams = new LinkedMultiValueMap<>();
            bodyParams.add("client_id", clientId);
            bodyParams.add("client_secret", clientSecret);
            bodyParams.add("grant_type", "authorization_code");
            bodyParams.add("code", authorizationCode);
            bodyParams.add("redirect_uri", "http://localhost:8081/resource-server/keycloak/redirect");

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(bodyParams, headers);

            ResponseEntity<Map> tokenResponse = restTemplate.exchange(tokenUrl, HttpMethod.POST, entity, Map.class);

            String accessToken = (String) tokenResponse.getBody().get("access_token");

            if (accessToken == null) {
                throw new RuntimeException("Failed to obtain access token");
            }

            // 使用獲取的 Token 請求用戶資訊
            String userInfoUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/userinfo";
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.set("Authorization", "Bearer " + accessToken);
            HttpEntity<String> userEntity = new HttpEntity<>(userHeaders);

            ResponseEntity<Map> userResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userEntity,
                    Map.class);
            Map<String, Object> userInfo = userResponse.getBody();

            if (userInfo != null) {
                log.info("User Info: {}", userInfo);
                return ResponseEntity.ok(userInfo);
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User info not found.");
            }
        } catch (Exception e) {
            log.error("Error retrieving user info", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error retrieving user info.");
        }
    }

}