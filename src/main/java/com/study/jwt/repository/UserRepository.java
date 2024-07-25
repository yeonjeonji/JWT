package com.study.jwt.repository;

import com.study.jwt.dto.JoinDto;
import com.study.jwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {


    Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);


}
