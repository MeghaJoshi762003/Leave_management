package com.wavemaker.repository;

import com.wavemaker.models.Employee;

import java.util.List;

public interface EmployeeRepository {
    Employee getEmployee(int userId);
    List<Employee> getAllEmployeesOfManager(int managerId);
    String getManagerMail(int empId);
    String getPassword(String email);
}
