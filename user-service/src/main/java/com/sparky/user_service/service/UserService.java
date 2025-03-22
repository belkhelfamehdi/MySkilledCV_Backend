package com.sparky.user_service.service;

import com.sparky.user_service.dto.RegisterRequest;
import com.sparky.user_service.dto.UserResponse;
import com.sparky.user_service.entity.User;
import com.sparky.user_service.exception.EmailAlreadyExistsException;
import com.sparky.user_service.repository.UserRepository;
import com.sparky.user_service.utils.UserMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public UserResponse registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("Email already in use!");
        }

        User user = new User(null, request.getEmail(), passwordEncoder.encode(request.getPassword()), request.getName(), new Date(), new Date());
        userRepository.save(user);

        return UserMapper.toDto(user);
    }

    public User authenticate(UserResponse input) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );

        return userRepository.findByEmail(input.getEmail())
                .orElseThrow();
    }


}