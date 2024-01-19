package com.javainuse.springsecurity.repository;

import com.javainuse.springsecurity.model.DAOUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<DAOUser, Long> {
    Optional<DAOUser> findByUsername(String username);
}
