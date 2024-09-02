package com.wavemaker.service;

import com.wavemaker.models.Employee;

import java.util.List;

public interface EmployeeService {
    Employee getEmployee(int userId);
    List<Employee> getAllEmployeesOfManager(int userId);
    String getManagerEmail(int userId);
}
