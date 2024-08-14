package com.distributed_system_design_lab.member_service_resource_server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.distributed_system_design_lab.member_service_resource_server.dao.KeycloakRepository;
import com.distributed_system_design_lab.member_service_resource_server.entity.Keycloak;

@Service
public class KeycloakService {
    @Autowired
    private KeycloakRepository keycloakRepository;

    public Keycloak saveKeycloakData(Keycloak keycloak) {
        return keycloakRepository.save(keycloak);
    }

    public Keycloak findByUsername(String username) {
        return keycloakRepository.findByUsername(username);
    }

    public Keycloak findByEmail(String email) {
        return keycloakRepository.findByEmail(email);
    }
}
