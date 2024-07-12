package com.distributed_system_design_lab.member_service_resource_server.service.impl;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.distributed_system_design_lab.member_service_resource_server.persistence.model.Foo;
import com.distributed_system_design_lab.member_service_resource_server.persistence.repository.IFooRepository;
import com.distributed_system_design_lab.member_service_resource_server.service.IFooService;

@Service
public class FooServiceImpl implements IFooService {

    private IFooRepository fooRepository;

    public FooServiceImpl(IFooRepository fooRepository) {
        this.fooRepository = fooRepository;
    }

    @Override
    public Optional<Foo> findById(Long id) {
        return fooRepository.findById(id);
    }

    @Override
    public Foo save(Foo foo) {
        return fooRepository.save(foo);
    }

    @Override
    public Iterable<Foo> findAll() {
        return fooRepository.findAll();
    }
}
