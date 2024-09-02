package com.wavemaker.repository.impl;
import com.wavemaker.models.Employee;
import com.wavemaker.repository.EmployeeRepository;
import com.wavemaker.utils.DBConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class EmployeeRepositoryImpl implements EmployeeRepository {
    public static final String GET_EMPLOYEE="SELECT * FROM EMPLOYEE WHERE ID=?";
    public static final String EMPLOYEE_OF_MANAGER="SELECT * FROM EMPLOYEE WHERE MGR_ID=?";
    private static final Logger log = LogManager.getLogger(LeaveRepositoryimpl.class);
    public static final String MANAGER_OF_EMPOYEE="SELECT MGR_ID FROM EMPLOYEE WHERE ID=?";
    public static final String GET_EMAIL="SELECT EMAIL FROM LOGIN WHERE EMP_ID=?";
    public static final String GET_PASSWORD="SELECT PASSWORD FROM LOGIN WHERE EMAIL=?";
    private Connection connection;

    public EmployeeRepositoryImpl() {
        connection = DBConnection.getConnection();
    }
    @Override
    public String getManagerMail(int empId)
    {
        try{
            PreparedStatement preparedStatement=connection.prepareStatement(MANAGER_OF_EMPOYEE);
            preparedStatement.setInt(1,empId);
            ResultSet resultSet=preparedStatement.executeQuery();
            resultSet.next();
            int mgrId=resultSet.getInt("MGR_ID");
            preparedStatement.close();
            resultSet.close();
            preparedStatement=connection.prepareStatement(GET_EMAIL);
            preparedStatement.setInt(1,mgrId);
            resultSet=preparedStatement.executeQuery();
            resultSet.next();
            String email=resultSet.getString("EMAIL");
            return email;
        }
        catch(SQLException e)
        {
            log.error(e);
        }
        return null;
    }

    @Override
    public Employee getEmployee(int userId) {
        Employee employee = null;
        try {
            PreparedStatement ps = connection.prepareStatement(GET_EMPLOYEE);
            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();
            rs.next();
            employee = new Employee(rs.getString("NAME"), rs.getString("PHONE_NO"), rs.getInt("MGR_ID"));
            employee.setId(userId);
            employee.setGender(rs.getString("GENDER"));
            return employee;
        } catch (SQLException e) {
            log.error(e);
        }
        return employee;
    }

    @Override
    public List<Employee> getAllEmployeesOfManager(int managerId) {
        try {
            PreparedStatement ps = connection.prepareStatement(EMPLOYEE_OF_MANAGER);
            ps.setInt(1, managerId);
            ResultSet rs = ps.executeQuery();
            List<Employee> employees = new ArrayList<Employee>();
            while (rs.next()) {
                Employee employee = new Employee(rs.getString("NAME"),
                        rs.getString("PHONE_NO"), rs.getInt("MGR_ID"));
                employee.setId(rs.getInt("ID"));
                employee.setGender(rs.getString("GENDER"));
                employee.setRole(rs.getString("ROLE"));
                employees.add(employee);
            }
            return employees;
        } catch (SQLException e) {
            log.error(e);
        }
        return null;
    }
    @Override
    public String getPassword(String email){
        try{
            PreparedStatement preparedStatement=connection.prepareStatement(GET_PASSWORD);
            preparedStatement.setString(1,email);
            ResultSet resultSet=preparedStatement.executeQuery();
            resultSet.next();
            String password=resultSet.getString("PASSWORD");
            preparedStatement.close();
            resultSet.close();
            return password;
        }catch(SQLException e){
            log.error(e);
        }
        return null;
    }

}
