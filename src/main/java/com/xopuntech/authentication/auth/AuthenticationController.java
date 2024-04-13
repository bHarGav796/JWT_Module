package com.xopuntech.authentication.auth;

// # End-Point the user an account and authenticate

import com.xopuntech.authentication.models.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/vi/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register/user")
    public ResponseEntity<?> user_register(
            @RequestBody RegisterRequest request
    ){
        User registeredUser = service.register(request, "USER");
        return ResponseEntity.ok(registeredUser);
    }


    @PostMapping("/register/admin")
    public ResponseEntity<?> admin_register(
            @RequestBody RegisterRequest request
    ){
        User registeredAdmin = service.register(request, "ADMIN");
        return ResponseEntity.ok(registeredAdmin);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(service.authenticate(request));

    }

}
