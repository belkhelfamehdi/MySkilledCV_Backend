package com.sparky.user_service.controller;


import com.sparky.user_service.config.JwtService;
import com.sparky.user_service.repository.UserRepository;
import com.sparky.user_service.request.AuthenticationRequest;
import com.sparky.user_service.request.RegisterRequest;
import com.sparky.user_service.response.AuthenticationResponse;
import com.sparky.user_service.service.AuthenticationService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationResponse> refreshToken(HttpServletRequest request) {
        String refreshToken = getRefreshTokenFromCookie(request);

        if (refreshToken != null) {
            String email = jwtService.extractUsername(refreshToken);
            var user = userRepository.findByEmail(email).orElse(null);

            if (user != null && jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);

                ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(Duration.ofDays(7))
                        .build();

                return ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, cookie.toString())
                        .body(AuthenticationResponse.builder()
                                .token(accessToken)
                                .build());
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }



}
