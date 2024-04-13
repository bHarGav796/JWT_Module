package com.xopuntech.authentication.repository;

import com.xopuntech.authentication.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


// # Repository for User Class -> Responsible to communicate with database
@Repository
public interface UserRepository extends JpaRepository<User, Integer> { //JpaRepository(Generic interface) -> bunch of methods
//    User = indicates the entity class that your repository is going to manage
//    Integer = specifies the data type of the primary key of your entity class
    Optional<User> findByEmail(String email);  // to find User by email
}
