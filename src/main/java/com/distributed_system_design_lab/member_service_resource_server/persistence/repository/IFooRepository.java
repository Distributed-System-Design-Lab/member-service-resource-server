package com.distributed_system_design_lab.member_service_resource_server.persistence.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.distributed_system_design_lab.member_service_resource_server.persistence.model.Foo;

public interface IFooRepository extends JpaRepository<Foo, Long> {
}
