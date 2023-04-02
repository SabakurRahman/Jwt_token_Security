package com.sabakurjwt.securityjwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {

    private  static  final String SECRATE_KEY = "452948404D6251655468576D5A7134743777217A25432A462D4A614E64526655";
    public String exterctUsername(String token) {
        return  extractClaims(token,Claims::getSubject);

    }
    public <T> T extractClaims(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String,Object> extraClims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInkey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username=exterctUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpaired(token);

    }

    private boolean isTokenExpaired(String token) {
       return extractExpiration(token).before(new Date());
    }


    private Date extractExpiration(String token) {
        return extractClaims(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){

        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInkey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInkey() {

        byte[] keyBytes = Decoders.BASE64.decode(SECRATE_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
