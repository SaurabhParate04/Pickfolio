package com.pickfolio.auth.util;

import com.pickfolio.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class RefreshTokenCleanupJob {

    private final RefreshTokenRepository refreshTokenRepository;
    private final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanupJob.class);

    @Scheduled(fixedRate = 12 * 60 * 60 * 1000) // every 12 hours
    @Transactional
    public void cleanUpExpiredTokens() {
        int deletedCount = refreshTokenRepository.deleteAllByExpiryDateBefore(Instant.now());
        logger.info("Cleanup Job: Deleted {} expired refresh tokens", deletedCount);
    }
}
