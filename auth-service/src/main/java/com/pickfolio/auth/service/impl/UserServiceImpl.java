package com.pickfolio.auth.service.impl;

import com.pickfolio.auth.domain.model.User;
import com.pickfolio.auth.domain.request.LoginRequest;
import com.pickfolio.auth.domain.request.RegisterRequest;
import com.pickfolio.auth.exception.InvalidCredentialsException;
import com.pickfolio.auth.exception.UsernameAlreadyExistsException;
import com.pickfolio.auth.repository.UserRepository;
import com.pickfolio.auth.service.UserService;
import org.slf4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(UserServiceImpl.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void registerUser(final RegisterRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new UsernameAlreadyExistsException(request.getUsername());
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .build();

        userRepository.save(user);
        logger.info("User registered successfully: {}", user.getUsername());
    }

    @Override
    @Transactional
    public String loginUser(LoginRequest request) {
        Optional<User> user = userRepository.findByUsername(request.getUsername());

        if (user.isEmpty()) {
            logger.debug("Login attempt failed: User not found with username {}", request.getUsername());
            throw new InvalidCredentialsException("No user found with username: " + request.getUsername());
        }

        if (!passwordEncoder.matches(request.getPassword(), user.get().getPassword())) {
            logger.debug("Login attempt failed: Invalid password for username {}", request.getUsername());
            throw new InvalidCredentialsException("Invalid password for user: " + request.getUsername());
        }

        logger.info("User logged in successfully: {}", user.get().getUsername());
        return "dummy-jwt-token for " + user.get().getUsername();
    }

}
