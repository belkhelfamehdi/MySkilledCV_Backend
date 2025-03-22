package com.sparky.user_service.responses;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true) // Permet le chaînage des setters
public class LoginResponse {
    private String token;
    private long expiresIn;
}
