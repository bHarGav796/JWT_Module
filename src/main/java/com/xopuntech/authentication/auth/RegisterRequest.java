package com.xopuntech.authentication.auth;

import lombok.*;

import javax.persistence.Entity;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;
}
