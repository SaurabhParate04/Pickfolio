package com.pickfolio.auth.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.pickfolio.auth.domain.properties.JwtProperties;
import com.pickfolio.auth.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtServiceImpl implements JwtService {

    private final Algorithm accessTokenAlgorithm;
    private final Algorithm refreshTokenAlgorithm;
    private final JwtProperties jwtProperties;

    private final Logger logger = LoggerFactory.getLogger(JwtServiceImpl.class);

    public JwtServiceImpl(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.accessTokenAlgorithm = Algorithm.HMAC256(jwtProperties.getAccessTokenSecret());
        this.refreshTokenAlgorithm = Algorithm.HMAC256(jwtProperties.getRefreshTokenSecret());
    }

    @Override
    public String generateAccessToken(String username) {
        Date issuedAt = new Date();
        Date expiresAt = new Date(issuedAt.getTime() + jwtProperties.getAccessTokenExpiryTime());

        return JWT.create()
                .withSubject(username)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(accessTokenAlgorithm);
    }


    @Override
    public boolean validateAccessToken(String token, String username) {
        try {
            DecodedJWT jwt = JWT.require(accessTokenAlgorithm)
                    .build()
                    .verify(token);

            String tokenUsername = jwt.getSubject();
            return tokenUsername.equals(username);
        } catch (JWTVerificationException ex) {
            logger.error("Invalid access token: {}", ex.getMessage());
            return false;
        }
    }

    @Override
    public String extractUsernameFromAccessToken(String token) {
        try {
            DecodedJWT jwt = JWT.require(accessTokenAlgorithm)
                    .build()
                    .verify(token);
            return jwt.getSubject();
        } catch (JWTVerificationException e) {
            logger.error("Failed to extract username from token: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public String generateRefreshToken(String username) {
        Date issuedAt = new Date();
        Date expiresAt = new Date(issuedAt.getTime() + jwtProperties.getRefreshTokenExpiryTime());

        return JWT.create()
                .withSubject(username)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(accessTokenAlgorithm);
    }

    @Override
    public boolean validateRefreshToken(String token, String username) {
        try {
            DecodedJWT jwt = JWT.require(refreshTokenAlgorithm)
                    .build()
                    .verify(token);

            String tokenUsername = jwt.getSubject();
            return tokenUsername.equals(username);
        } catch (JWTVerificationException ex) {
            logger.error("Invalid refresh token: {}", ex.getMessage());
            return false;
        }
    }

    @Override
    public String extractUsernameFromRefreshToken(String token) {
        try {
            DecodedJWT jwt = JWT.require(refreshTokenAlgorithm)
                    .build()
                    .verify(token);
            return jwt.getSubject();
        } catch (JWTVerificationException e) {
            logger.error("Failed to extract username from refresh token: {}", e.getMessage());
            return null;
        }
    }

}
