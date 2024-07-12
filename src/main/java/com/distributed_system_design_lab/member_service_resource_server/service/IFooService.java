package com.distributed_system_design_lab.member_service_resource_server.service;

import java.util.Optional;

import com.distributed_system_design_lab.member_service_resource_server.persistence.model.Foo;


public interface IFooService {
    Optional<Foo> findById(Long id);

    Foo save(Foo foo);
    
    Iterable<Foo> findAll();

}
