package com.wavemaker.service;

public interface TokenService {
    String generateToken(int userId);

    int validateToken(String token);
}
