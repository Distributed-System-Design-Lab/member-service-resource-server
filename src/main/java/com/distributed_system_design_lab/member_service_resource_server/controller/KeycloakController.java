package com.distributed_system_design_lab.member_service_resource_server.controller;

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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/keycloak")
public class KeycloakController {

    private static final Logger log = LoggerFactory.getLogger(KeycloakController.class);

    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/redirect")
    public void keycloakRedirect(@RequestParam("code") String code, HttpServletResponse response) throws IOException {
        String clientId = "peoplesystem";
        String redirectUri = "http://localhost:8081/resource-server/keycloak/redirect";
        String clientSecret = "WCQaVZubI44qHLgCKaOnZJ5LbQQfwyap";
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
}
