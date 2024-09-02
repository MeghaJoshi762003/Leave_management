package com.wavemaker.service.impl;
import com.wavemaker.models.Employee;
import com.wavemaker.repository.impl.EmployeeRepositoryImpl;
import com.wavemaker.service.EmployeeService;
import java.util.List;

public class EmployeeServiceImpl implements EmployeeService {

    private EmployeeRepositoryImpl employeeRepository;

    public EmployeeServiceImpl() {
        employeeRepository = new EmployeeRepositoryImpl();
    }

    @Override
    public Employee getEmployee(int userId) {
        return employeeRepository.getEmployee(userId);
    }

    @Override
    public List<Employee> getAllEmployeesOfManager(int userId) {
        return employeeRepository.getAllEmployeesOfManager(userId);
    }

    @Override
    public String getManagerEmail(int userId) {
        return employeeRepository.getManager(userId);
    }
}
