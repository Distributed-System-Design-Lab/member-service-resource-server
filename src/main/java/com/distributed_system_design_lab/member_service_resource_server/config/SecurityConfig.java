package com.distributed_system_design_lab.member_service_resource_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
                .withJwkSetUri("http://localhost:8083/auth/realms/PeopleSystem/protocol/openid-connect/certs").build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.GET, "/user/info", "/api/foos/**")
                        .hasAuthority("SCOPE_read")
                        .requestMatchers(HttpMethod.POST, "/api/foos")
                        .hasAuthority("SCOPE_write")
                        .anyRequest()
                        .authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt());

        return http.build();
    }
}