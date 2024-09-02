package com.wavemaker.repository.impl;

import com.wavemaker.repository.LoginRepository;
import com.wavemaker.utils.DBConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.*;

public class LoginRepositoryImpl implements LoginRepository {
    public static final String EMP_LOGIN = "SELECT EMP_ID FROM LOGIN WHERE EMAIL=? AND PASSWORD=?";
    public static final String EMP_EMAIL = "SELECT EMP_ID FROM LOGIN WHERE EMAIL=?";
    private static final Logger log = LogManager.getLogger(LoginRepositoryImpl.class);
    Connection connection;

    public LoginRepositoryImpl() {
        connection = DBConnection.getConnection();
    }

    public int authenticate(String username, String password) {
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(EMP_LOGIN);
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, password);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("EMP_ID");
            } else
                return -1;
        } catch (SQLException e) {
            log.error(e);
        }
        return -1;
    }

    public boolean validateUser(int userId, String email) {
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(EMP_EMAIL);
            preparedStatement.setString(1, email);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("EMP_ID") == userId;
            }
        } catch (SQLException e) {
            log.error(e);
        }
        return false;
    }

}
