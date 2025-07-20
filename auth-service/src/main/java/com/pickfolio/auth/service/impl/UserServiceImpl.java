package com.pickfolio.auth.service.impl;

import com.pickfolio.auth.domain.model.RefreshToken;
import com.pickfolio.auth.domain.model.User;
import com.pickfolio.auth.domain.properties.JwtProperties;
import com.pickfolio.auth.domain.request.LoginRequest;
import com.pickfolio.auth.domain.request.LogoutRequest;
import com.pickfolio.auth.domain.request.RefreshRequest;
import com.pickfolio.auth.domain.request.RegisterRequest;
import com.pickfolio.auth.domain.response.LoginResponse;
import com.pickfolio.auth.exception.InvalidCredentialsException;
import com.pickfolio.auth.exception.UsernameAlreadyExistsException;
import com.pickfolio.auth.repository.RefreshTokenRepository;
import com.pickfolio.auth.repository.UserRepository;
import com.pickfolio.auth.service.JwtService;
import com.pickfolio.auth.service.UserService;
import org.slf4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(UserServiceImpl.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, JwtProperties jwtProperties, RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    @Transactional
    public void registerUser(final RegisterRequest request) {
        String username = request.getUsername().trim();
        if (userRepository.findByUsername(username).isPresent()) {
            throw new UsernameAlreadyExistsException(username);
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .build();

        userRepository.save(user);
        logger.info("User registered successfully: {}", user.getUsername());
    }

    @Override
    @Transactional
    public LoginResponse loginUser(LoginRequest request) {
        Optional<User> user = userRepository.findByUsername(request.getUsername());

        if (user.isEmpty()) {
            logger.debug("Login attempt failed: User not found with username {}", request.getUsername());
            throw new InvalidCredentialsException("No user found with username: " + request.getUsername());
        }

        if (!passwordEncoder.matches(request.getPassword(), user.get().getPassword())) {
            logger.debug("Login attempt failed: Invalid password for username {}", request.getUsername());
            throw new InvalidCredentialsException("Invalid password for user: " + request.getUsername());
        }

        String generatedAccessToken = jwtService.generateAccessToken(request.getUsername());
        String generatedRefreshToken = jwtService.generateRefreshToken(request.getUsername());

        logger.debug("Generated access token for user: {}", request.getUsername());
        logger.debug("Generated refresh token for user: {}", request.getUsername());
        logger.info("User logged in successfully: {}", user.get().getUsername());

        // Delete any existing refresh tokens for the user
        refreshTokenRepository.deleteAllByUserAndDeviceInfo(user.get(), request.getDeviceInfo());
        logger.debug("Deleted existing refresh tokens for user: {} with device: {}", user.get().getUsername(), request.getDeviceInfo());

        // Create and save the new refresh token
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(generatedRefreshToken);
        refreshToken.setExpiryDate(Instant.now().plus(Duration.ofMillis(jwtProperties.getRefreshTokenExpiryTime())));
        refreshToken.setUser(user.get());
        refreshToken.setDeviceInfo(request.getDeviceInfo());
        refreshTokenRepository.save(refreshToken);

        return new LoginResponse(generatedAccessToken, generatedRefreshToken);
    }

    @Override
    @Transactional
    public LoginResponse refreshAccessToken(RefreshRequest request) {
        String oldRefreshToken = request.getRefreshToken();

        if (oldRefreshToken == null || oldRefreshToken.isEmpty()) {
            logger.error("Refresh token attempt failed: Refresh token is null or empty");
            throw new InvalidCredentialsException("Can't refresh access token: Refresh token is null or empty");
        }

        String username;
        try {
            username = jwtService.extractUsernameFromRefreshToken(oldRefreshToken);
        } catch (Exception e) {
            logger.error("Failed to extract username from refresh token", e);
            throw new InvalidCredentialsException("Invalid refresh token");
        }

        // Validate user exists
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logger.debug("Refresh token attempt failed: No user found with username {}", username);
                    return new InvalidCredentialsException("No user found with username: " + username);
                });

        // Validate the token
        if (!jwtService.validateRefreshToken(oldRefreshToken, username)) {
            logger.error("Refresh token attempt failed: Invalid refresh token for user {}", username);
            throw new InvalidCredentialsException("Invalid refresh token for user: " + username);
        }

        // Delete the old refresh token entry from DB
        refreshTokenRepository.deleteByToken(oldRefreshToken);

        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(username);
        String newRefreshToken = jwtService.generateRefreshToken(username);

        // Save new refresh token in DB
        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setUser(user);
        tokenEntity.setToken(newRefreshToken);
        tokenEntity.setExpiryDate(Instant.now().plus(Duration.ofMillis(jwtProperties.getRefreshTokenExpiryTime())));
        tokenEntity.setDeviceInfo(request.getDeviceInfo());
        refreshTokenRepository.save(tokenEntity);

        logger.debug("Refreshed tokens for user: {}", username);

        return new LoginResponse(newAccessToken, newRefreshToken);
    }


    @Override
    @Transactional
    public void logoutUser(LogoutRequest request) {
        if (request.getRefreshToken() == null || request.getRefreshToken().isEmpty()) {
            logger.error("Logout failed: refresh token is null or empty");
            throw new InvalidCredentialsException("Refresh token must be provided to logout");
        }

        refreshTokenRepository.findByToken(request.getRefreshToken())
                .ifPresentOrElse(
                        token -> {
                            refreshTokenRepository.delete(token);
                            logger.info("User logged out, refresh token invalidated: {}", token.getToken());
                        },
                        () -> {
                            logger.warn("Logout attempted with non-existing token: {}", request.getRefreshToken());
                            // Always return success to avoid revealing whether the token exists or not.
                            // Client won’t be affected because they’ll delete the token on their side anyway.
                        }
                );
    }

    @Override
    @Transactional
    public void logoutUserFromAllDevices(LogoutRequest request) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid refresh token"));

        User user = refreshToken.getUser();
        int deletedCount = refreshTokenRepository.deleteAllByUser(user);
        logger.info("User {} logged out from all devices. {} tokens deleted", user.getUsername(), deletedCount);
    }

}
