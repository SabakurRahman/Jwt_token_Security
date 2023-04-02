package com.sabakurjwt.securityjwt.auth;

import com.sabakurjwt.securityjwt.UserReposiory;
import com.sabakurjwt.securityjwt.config.JwtService;
import com.sabakurjwt.securityjwt.entity.Role;
import com.sabakurjwt.securityjwt.entity.User;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticationService {

    private final UserReposiory userReposiory;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {

        var user = User.builder()
                .fristName(request.getFristname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

            userReposiory.save(user);
       var jwttoken =jwtService.generateToken(user);
       return AuthenticationResponse.builder()
               .token(jwttoken)
               .build();

        
        
    }

    public AuthenticationResponse authentication(AuthenticationRequest request) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user= userReposiory.findByEmail(request.getEmail())
                .orElseThrow();

        var jwttoken =jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwttoken)
                .build();
    }
}
