package com.xopuntech.authentication.config;

// # We need to Bind the Filter

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;



@Configuration
@EnableWebSecurity
@RequiredArgsConstructor

public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;  //final -> so that automatically injected by spring
    private final AuthenticationProvider authenticationProvider;


    @Bean // At the start-up Spring Security will look for a bean of type SecurityFilterChain -> responsible to configure all the Http security of our Application
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()  //Whitelist -> End-points that do not require any Authentication/tokens  (Create an account)
                    .antMatchers("/api/vi/auth/**") //Pass a list of String/ List of patterns
                    .permitAll() //Permit all the request within this list
                    .anyRequest()
                    .authenticated() //Any other request should be authenticated
                .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //OncePerRequestFilter -> Session State should not be store, Ensures that every request is authenticated
                .and()
                .authenticationProvider(authenticationProvider) // Tell Spring which authenticationProvide we want to use.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); //To use the jwt Filter that we created


        return http.build();
    }
}
