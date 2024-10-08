package com.distributed_system_design_lab.member_service_resource_server.controller;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
    private String clientSecret = "jD6SgkVLmorD0FoHlJlfKMbWyi5FYkg2";
    private String realm = "PeopleSystem";

    @GetMapping("/redirect")
    public void keycloakRedirect(@RequestParam("code") String code, HttpServletResponse response)
            throws IOException {
        String redirectUri = "http://localhost:8081/resource-server/keycloak/redirect";
        String tokenUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token";

        try {
            log.info("Received authorization code: {}", code);

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

            log.info("Access Token: {}", accessToken);
            log.info("Refresh Token: {}", refreshToken);

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

            log.info("User Info: {}", userInfo);

            String preferredUsername = (String) userInfo.get("preferred_username");
            if (preferredUsername == null) {
                throw new RuntimeException("Failed to retrieve user info");
            }

            keycloakService.deleteByUsername(preferredUsername);

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

            response.setHeader("Set-Cookie", "refreshToken=; Path=/; Max-Age=0; SameSite=Lax");
            response.addHeader("Set-Cookie", "authorizationCode=" + code + "; Path=/; SameSite=Lax");
            response.addHeader("Set-Cookie", "refreshToken=" + refreshToken + "; Path=/; SameSite=Lax");
            response.addHeader("Set-Cookie", "accessToken=" + accessToken + "; Path=/; SameSite=Lax");

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

    @CrossOrigin
    @GetMapping("/introspect")
    public ResponseEntity<?> introspectToken(@RequestParam("token") String token) {
        String introspectUrl = "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token/introspect";

        try {
            MultiValueMap<String, String> bodyParams = new LinkedMultiValueMap<>();
            bodyParams.add("client_id", clientId);
            bodyParams.add("client_secret", clientSecret);
            bodyParams.add("token", token);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(bodyParams, headers);

            ResponseEntity<Map> introspectResponse = restTemplate.exchange(introspectUrl, HttpMethod.POST, entity,
                    Map.class);
            Map<String, Object> introspectionResult = introspectResponse.getBody();

            if (introspectionResult != null && Boolean.TRUE.equals(introspectionResult.get("active"))) {
                return ResponseEntity.ok(introspectionResult);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is not active or invalid.");
            }
        } catch (Exception e) {
            log.error("Error introspecting token", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error introspecting token.");
        }
    }

    @CrossOrigin
    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@RequestBody Map<String, String> userDetails,
            @RequestParam("accessToken") String accessToken) {

        try {
            String url = "http://localhost:8083/auth/admin/realms/" + realm + "/users";
            Map<String, Object> userRepresentation = new HashMap<>();
            userRepresentation.put("username", userDetails.get("username"));
            userRepresentation.put("email", userDetails.get("email"));
            userRepresentation.put("firstName", userDetails.get("firstName"));
            userRepresentation.put("lastName", userDetails.get("lastName"));
            userRepresentation.put("enabled", true);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userRepresentation, headers);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.ok("User created successfully.");
            } else {
                return ResponseEntity.status(response.getStatusCode()).body("Failed to create user.");
            }

        } catch (Exception e) {
            log.error("Error creating user", e);
            return ResponseEntity.status(500).body("Error creating user.");
        }
    }

    // @GetMapping("/getUserInfo")
    // public ResponseEntity<?> getUserInfo(@RequestParam("authorizationCode")
    // String authorizationCode) {
    // String tokenUrl =
    // "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/token";

    // try {
    // MultiValueMap<String, String> bodyParams = new LinkedMultiValueMap<>();
    // bodyParams.add("client_id", clientId);
    // bodyParams.add("client_secret", clientSecret);
    // bodyParams.add("grant_type", "authorization_code");
    // bodyParams.add("code", authorizationCode);
    // bodyParams.add("redirect_uri",
    // "http://localhost:8081/resource-server/keycloak/redirect");

    // HttpHeaders headers = new HttpHeaders();
    // headers.set("Content-Type", "application/x-www-form-urlencoded");
    // HttpEntity<MultiValueMap<String, String>> entity = new
    // HttpEntity<>(bodyParams, headers);

    // ResponseEntity<Map> tokenResponse = restTemplate.exchange(tokenUrl,
    // HttpMethod.POST, entity, Map.class);
    // String accessToken = (String) tokenResponse.getBody().get("access_token");

    // if (accessToken == null) {
    // throw new RuntimeException("Failed to obtain access token");
    // }

    // String userInfoUrl =
    // "http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/userinfo";
    // HttpHeaders userHeaders = new HttpHeaders();
    // userHeaders.set("Authorization", "Bearer " + accessToken);
    // HttpEntity<String> userEntity = new HttpEntity<>(userHeaders);

    // ResponseEntity<Map> userResponse = restTemplate.exchange(userInfoUrl,
    // HttpMethod.GET, userEntity,
    // Map.class);
    // Map<String, Object> userInfo = userResponse.getBody();

    // if (userInfo != null) {
    // return ResponseEntity.ok(userInfo);
    // } else {
    // return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User info not
    // found.");
    // }
    // } catch (Exception e) {
    // log.error("Error retrieving user info", e);
    // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error
    // retrieving user info.");
    // }
    // }
}
