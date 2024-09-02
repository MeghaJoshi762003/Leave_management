package com.wavemaker.service;

public interface LoginService {
    int authenticate(String username, String password);
    boolean validateUser(int userId, String email);

}
