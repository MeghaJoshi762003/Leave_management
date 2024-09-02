package com.wavemaker.models;

public class EmployeeDTO {
    private String name;
    private String phoneNumber;
    private String gender;
    private int id;
    public EmployeeDTO(String name, String phoneNumber, String gender,int id) {
        this.name = name;
        this.phoneNumber = phoneNumber;
        this.gender = gender;
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }
}
