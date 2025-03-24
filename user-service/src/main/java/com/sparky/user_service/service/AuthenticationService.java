package com.sparky.user_service.service;

import com.sparky.user_service.config.JwtService;
import com.sparky.user_service.entity.Role;
import com.sparky.user_service.entity.User;
import com.sparky.user_service.repository.UserRepository;
import com.sparky.user_service.request.AuthenticationRequest;
import com.sparky.user_service.request.RegisterRequest;
import com.sparky.user_service.response.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        // On renvoie le refresh token dans un cookie HTTP-Only
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true) // Utilise secure si ton app est en HTTPS
                .path("/")
                .maxAge(Duration.ofDays(7)) // 7 jours
                .build();

        return AuthenticationResponse.builder()
                .token(accessToken)
                .refreshTokenCookie(cookie)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        // On renvoie le refresh token dans un cookie HTTP-Only
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofDays(7))
                .build();

        return AuthenticationResponse.builder()
                .token(accessToken)
                .refreshTokenCookie(cookie)
                .build();
    }

}
