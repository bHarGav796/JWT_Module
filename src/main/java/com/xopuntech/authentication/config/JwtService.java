package com.xopuntech.authentication.config;
// # Class that can manipulate the Jwt token
import com.xopuntech.authentication.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;
@Service // make it a managed bean
public class JwtService {
    private static final String SECRET_KEY = "7292444fecebe059de82bd1f73f33c633bb9a5dab3f27db338a9a6e1e1973ad7";
    // 1.  Extract all claims from the token
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()  //to parse the token
                .setSigningKey(getSignInKey()) //when we try to create/generate/decode we need the signing key
                .build() //to build because it is a builder
                .parseClaimsJws(token)
                .getBody();
    }
    // 2. Extract a single claims
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    // 3. Extract a UserName claims
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }
    // 4. Generate Token
        // a) using extraClaims
        public String generateToken(
            Map<String, Object> extraClaims,
                    UserDetails userDetails
        ){
            List<String> roles = getRolesFromUserDetails(userDetails); // Extract user roles to include in the PayLoad
            extraClaims.put("roles", roles);

            return Jwts
                    .builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))  //valid upto 24 hrs
                    .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                    .compact(); //method to generate and return the token
        }
    // Helper method to extract roles from extra claims
    private List<String> getRolesFromUserDetails(UserDetails userDetails) {
        List<String> roles = new ArrayList<>();
        if (userDetails instanceof User) {
            User user = (User) userDetails;
            for (GrantedAuthority authority : user.getAuthorities()) {
                roles.add(authority.getAuthority());
            }
        }
        return roles;
    }
    // b) using only userDetails
        public String generateToken(UserDetails userDetails){
            return generateToken(new HashMap<>(),userDetails);
        }
    // 6. Check/Validate a token
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // decode our secrete key in Base64
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
