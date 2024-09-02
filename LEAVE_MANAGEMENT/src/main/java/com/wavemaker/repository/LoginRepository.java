package com.wavemaker.repository;

public interface LoginRepository {
    int authenticate(String username, String password);
    boolean validateUser(int userId,String email);
}
