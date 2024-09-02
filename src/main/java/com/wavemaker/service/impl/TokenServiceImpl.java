package com.wavemaker.service.impl;

import com.wavemaker.service.TokenService;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class TokenServiceImpl implements TokenService {
    private final Map<String, Integer> tokenStore = new ConcurrentHashMap<>();

    @Override
    public String generateToken(int userId) {
        String token = UUID.randomUUID().toString();
        tokenStore.put(token, userId);
        return token;
    }

    @Override
    public int validateToken(String token) {
        Integer userId = tokenStore.get(token);
        return (userId != null) ? userId : -1;
    }
}
