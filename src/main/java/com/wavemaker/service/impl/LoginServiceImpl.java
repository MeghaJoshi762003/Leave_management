package com.wavemaker.service.impl;

import com.wavemaker.repository.impl.LoginRepositoryImpl;
import com.wavemaker.service.LoginService;

public class LoginServiceImpl implements LoginService {
    private LoginRepositoryImpl loginRepositoryImpl;

    public LoginServiceImpl() {
        loginRepositoryImpl = new LoginRepositoryImpl();
    }

    public int authenticate(String username, String password) {
        return loginRepositoryImpl.authenticate(username, password);
    }

    public boolean validateUser(int userId, String email) {
        return loginRepositoryImpl.validateUser(userId, email);
    }
}
