package com.pickfolio.auth.service;

import com.pickfolio.auth.domain.request.LoginRequest;
import com.pickfolio.auth.domain.request.RegisterRequest;

public interface UserService {
    void registerUser(RegisterRequest request);
    String loginUser(LoginRequest request);
}
