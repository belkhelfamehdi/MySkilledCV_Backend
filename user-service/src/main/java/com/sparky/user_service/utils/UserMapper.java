package com.sparky.user_service.utils;

import com.sparky.user_service.dto.UserResponse;
import com.sparky.user_service.entity.User;

public class UserMapper {
    public static UserResponse toDto(User user) {
        return new UserResponse(user.getId(), user.getName(), user.getEmail());
    }
}