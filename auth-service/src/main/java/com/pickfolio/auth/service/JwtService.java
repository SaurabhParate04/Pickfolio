package com.pickfolio.auth.service;

public interface JwtService {

    String generateAccessToken(String username);

    boolean validateAccessToken(String token, String username);

    String extractUsernameFromAccessToken(String token);

    String generateRefreshToken(String username);

    boolean validateRefreshToken(String token, String username);

    String extractUsernameFromRefreshToken(String token);

}
