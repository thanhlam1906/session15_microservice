package com.example.identityservice.service;

import com.example.identityservice.config.JwtUtil;
import com.example.identityservice.dto.LoginRequest;
import com.example.identityservice.dto.LoginResponse;
import com.example.identityservice.dto.RefreshRequest;
import com.example.identityservice.entity.AppUser;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.repository.AppUserRepository;
import com.example.identityservice.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AppUserRepository appUserRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public LoginResponse login(LoginRequest request) {
        AppUser user = appUserRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid username or password");
        }

        List<String> permissions = Arrays.asList(user.getPermissions().split(","));
        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), permissions);
        String refreshToken = jwtUtil.generateRefreshToken();

        refreshTokenRepository.deleteByUsername(user.getUsername());

        RefreshToken rt = RefreshToken.builder()
                .token(refreshToken)
                .username(user.getUsername())
                .expiryDate(Instant.now().plusMillis(jwtUtil.getRefreshTokenExpirationMs()))
                .build();
        refreshTokenRepository.save(rt);

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }

    @Transactional
    public LoginResponse refresh(RefreshRequest request) {
        RefreshToken existing = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (existing.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(existing);
            throw new RuntimeException("Refresh token expired");
        }

        refreshTokenRepository.delete(existing);

        String username = existing.getUsername();
        AppUser user = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<String> permissions = Arrays.asList(user.getPermissions().split(","));
        String accessToken = jwtUtil.generateAccessToken(username, permissions);
        String newRefreshToken = jwtUtil.generateRefreshToken();

        RefreshToken rt = RefreshToken.builder()
                .token(newRefreshToken)
                .username(username)
                .expiryDate(Instant.now().plusMillis(jwtUtil.getRefreshTokenExpirationMs()))
                .build();
        refreshTokenRepository.save(rt);

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .build();
    }

    public void logout(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Missing token");
        }

        String token = authHeader.substring(7);

        if (!jwtUtil.validateToken(token)) {
            throw new RuntimeException("Invalid token");
        }

        String jti = jwtUtil.extractJti(token);
        long ttlMs = jwtUtil.getRemainingTtlMs(token);

        if (ttlMs > 0) {
            redisTemplate.opsForValue().set("blacklist:" + jti, "revoked", Duration.ofMillis(ttlMs));
        }
    }
}
