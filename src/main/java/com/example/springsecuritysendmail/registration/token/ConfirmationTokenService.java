package com.example.springsecuritysendmail.registration.token;


import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@AllArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public void saveConfirmationToken(ConfirmationToken token) {
        confirmationTokenRepository.save(token);
    }

    public void updateConfirmationToken(Long appUserId, String token) {
        ConfirmationToken tokenRepositoryByToken = confirmationTokenRepository.findByAppUser(appUserId).get();
        tokenRepositoryByToken.setToken(token);
        tokenRepositoryByToken.setExpiresAt(LocalDateTime.now());
        confirmationTokenRepository.save(tokenRepositoryByToken);
    }

    public Optional<ConfirmationToken> getToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }

    public int setConfirmedAt(String token) {
        return confirmationTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }

}
