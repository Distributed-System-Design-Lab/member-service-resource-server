package com.distributed_system_design_lab.member_service_resource_server.controller;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.distributed_system_design_lab.member_service_resource_server.entity.Keycloak;
import com.distributed_system_design_lab.member_service_resource_server.service.KeycloakService;

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
    private String clientSecret = "ionH1sel1E2cKwWxVMt67BoPRAjOCn0j";

    @GetMapping("/redirect")
    public void keycloakRedirect(@RequestParam("code") String code, HttpServletResponse response)
            throws IOException {
        String redirectUri = "http://localhost:8081/resource-server/keycloak/redirect";
        String tokenUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token";

        try {
            // Token Request
            MultiValueMap<String, String> tokenParams = new LinkedMultiValueMap<>();
            tokenParams.add("client_id", clientId);
            tokenParams.add("client_secret", clientSecret);
            tokenParams.add("code", code);
            tokenParams.add("grant_type", "authorization_code");
            tokenParams.add("redirect_uri", redirectUri);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(tokenParams, headers);

            ResponseEntity<Map> tokenResponse = restTemplate.exchange(tokenUrl, HttpMethod.POST, entity, Map.class);
            String accessToken = (String) tokenResponse.getBody().get("access_token");
            String refreshToken = (String) tokenResponse.getBody().get("refresh_token");

            if (accessToken == null || refreshToken == null) {
                throw new RuntimeException("Failed to obtain access token");
            }

            // Request User Info
            String userInfoUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/userinfo";
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.set("Authorization", "Bearer " + accessToken);
            HttpEntity<String> userEntity = new HttpEntity<>(userHeaders);

            ResponseEntity<Map> userResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userEntity,
                    Map.class);
            Map<String, Object> userInfo = userResponse.getBody();

            String preferredUsername = (String) userInfo.get("preferred_username");
            if (preferredUsername == null) {
                throw new RuntimeException("Failed to retrieve user info");
            }

            // Save or Update User
            Keycloak user = new Keycloak();
            user.setPreferredUsername(preferredUsername);
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

            // Redirect
            response.sendRedirect(
                    "http://localhost:3000/" + "?username=" + preferredUsername + "&email=" + user.getEmail()
                            + "&token=" + accessToken);
        } catch (Exception e) {
            log.error("Error processing OAuth redirect", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing OAuth redirect");
        }
    }

    @CrossOrigin
    @GetMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam("refreshToken") String refreshToken) {
        String logoutUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/logout";

        try {
            // Revoke Token
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("refresh_token", refreshToken);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

            restTemplate.exchange(logoutUrl, HttpMethod.POST, entity, String.class);

            // Delete User from the Database
            Keycloak keycloakUser = keycloakService.findByAccessToken(refreshToken);
            if (keycloakUser != null) {
                keycloakService.deleteByUsername(keycloakUser.getPreferredUsername());
            }

            return ResponseEntity.ok("Logout successful");
        } catch (Exception e) {
            log.error("Logout failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Logout failed");
        }
    }

    @GetMapping("/getUserInfo")
    public ResponseEntity<?> getUserInfo(@RequestParam("authorizationCode") String authorizationCode) {
        String tokenUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token";

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

            String userInfoUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/userinfo";
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.set("Authorization", "Bearer " + accessToken);
            HttpEntity<String> userEntity = new HttpEntity<>(userHeaders);

            ResponseEntity<Map> userResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userEntity,
                    Map.class);
            Map<String, Object> userInfo = userResponse.getBody();

            if (userInfo != null) {
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
