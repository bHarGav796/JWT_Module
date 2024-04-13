package com.xopuntech.authentication.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// # First thing that will intercept our HTTP request is the JwtAuthFilter

@Component // to make this class a managed bean
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {  //To make the Filter active every-time we get a request -> extend OncePerRequestFilter

    private final JwtService jwtService; // Class that will manipulate the Jwt token
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, //request -> our request
                                    HttpServletResponse response, //response-> our response
                                    FilterChain filterChain  // chain of responsibility design pattern, has a list of other filters we want to execute
    ) throws ServletException, IOException {

// # First thing that the JwtAuthFilter does is check the Jwt Token

        final String authHeader = request.getHeader("Authorization"); // authHeader(extract it from the request) -> When we make a call we need to pass the Jwt authentication token within a header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); //pass to next filter
            return; //to stop execution of rest of the filters
        }

        final String jwt;
        jwt = authHeader.substring(7); //Extract the Jwt token from the authHeader

// # After checking the Jwt token-> Call the UserDetailsService to check if user exist in our DB -> It needs, JwtService to extract the username

        final String userEmail;
        userEmail = jwtService.extractUsername(jwt);

        // After we have our UserName
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {  //Check if userEmail!=null from the token, check user is authenticated or not
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) { // Check if token is valid, (yes) ->  update SecurityContextHolder
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );  //authToken needed by Spring
                authToken.setDetails(  // extend/enforce our authToken with details of our request
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

// #  final step-> update SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response); //pass the control to the next filter
    }
}
