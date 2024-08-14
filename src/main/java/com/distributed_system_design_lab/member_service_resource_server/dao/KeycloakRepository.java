package com.distributed_system_design_lab.member_service_resource_server.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.distributed_system_design_lab.member_service_resource_server.entity.Keycloak;

@Repository
public interface KeycloakRepository extends JpaRepository<Keycloak, Long> {

    Keycloak findByUsername(String username);

    Keycloak findByEmail(String email);
}
