package com.xopuntech.authentication.config;

// # Class that implements the UserDetailsService

import org.springframework.security.authentication.AuthenticationProvider;
import com.xopuntech.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration  //At start-up Spring will implement & inject all the beans we declare within this class
@RequiredArgsConstructor  // In-case we want to inject something
public class ApplicationConfig {

    private final UserRepository repository;

    @Bean //Bean -> always public
    public UserDetailsService userDetailsService(){
        return username -> repository.findByEmail(username)
                .orElseThrow(()-> new UsernameNotFoundException("User not Found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){  // dao (data access object) -> responsible to fetch userDeatils, encode Password & so on.
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService()); //we need to tell the authentication provide which userDetails service to use, in order to fetch information about our user.
        authProvider.setPasswordEncoder(passwordEncoder()); //Which password Encode we are using in our application.
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)throws Exception{  //responsible to manage the authentication-> has a bunch of methods
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
