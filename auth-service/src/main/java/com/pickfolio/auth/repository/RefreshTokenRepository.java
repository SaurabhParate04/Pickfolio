package com.pickfolio.auth.repository;

import com.pickfolio.auth.domain.model.RefreshToken;
import com.pickfolio.auth.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    List<RefreshToken> findAllByUser(User user);
    void deleteByToken(String token);
    int deleteAllByUser(User user);
    void deleteAllByUserAndDeviceInfo(User user, String deviceInfo);
}
