package com.sabakurjwt.securityjwt;

import com.sabakurjwt.securityjwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserReposiory extends JpaRepository<User,Integer> {

    Optional<User> findByEmail(String email);
}
