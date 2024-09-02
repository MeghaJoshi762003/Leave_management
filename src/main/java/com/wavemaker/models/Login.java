package com.wavemaker.models;
public class Login {
    private int emp_id;
    private String email;
    private String password;
    public Login(int emp_id, String email, String password) {
        this.emp_id = emp_id;
        this.email = email;
        this.password = password;
    }

    public int getEmp_id() {
        return emp_id;
    }

    public void setEmp_id(int emp_id) {
        this.emp_id = emp_id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
