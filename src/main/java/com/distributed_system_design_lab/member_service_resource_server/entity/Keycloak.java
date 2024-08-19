package com.distributed_system_design_lab.member_service_resource_server.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "keycloak", indexes = {
        @Index(name = "inx_username", columnList = "username"),
        @Index(name = "inx_email", columnList = "email")
})
public class Keycloak {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String username;

    @Column(length = 255)
    private String email;

    @Column(length = 255)
    private String givenName;

    @Column(length = 255)
    private String familyName;

    @Column
    private Boolean emailVerified;

    @Column(length = 255)
    private String sub;

    @Column(columnDefinition = "TEXT")
    private String accessToken;

    @Column(columnDefinition = "TEXT")
    private String refreshToken;

    @Column(name = "expires_in")
    private Instant expiresIn;

    @Column(name = "issued_at", updatable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Instant issuedAt;

    // Default constructor
    public Keycloak() {
    }

    // Parameterized constructor
    public Keycloak(String username, String email, String givenName, String familyName, Boolean emailVerified,
            String sub, String accessToken, String refreshToken, Instant expiresIn, Instant issuedAt) {
        this.username = username;
        this.email = email;
        this.givenName = givenName;
        this.familyName = familyName;
        this.emailVerified = emailVerified;
        this.sub = sub;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.issuedAt = issuedAt;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Instant getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Instant expiresIn) {
        this.expiresIn = expiresIn;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    @Override
    public String toString() {
        return "Keycloak{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", givenName='" + givenName + '\'' +
                ", familyName='" + familyName + '\'' +
                ", emailVerified=" + emailVerified +
                ", sub='" + sub + '\'' +
                ", accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", expiresIn=" + expiresIn +
                ", issuedAt=" + issuedAt +
                '}';
    }
}