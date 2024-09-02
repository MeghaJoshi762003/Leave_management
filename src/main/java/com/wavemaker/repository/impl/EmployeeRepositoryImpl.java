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
    public static final String MANAGER_OF_EMPOYEE="SELECT B.EMAIL FROM EMPLOYEE AS A SELF JOIN EMPLOYEE AS B ON A.MGR_ID=B.ID WHERE A.ID=?";
    private Connection connection;

    public EmployeeRepositoryImpl() {
        connection = DBConnection.getConnection();
    }
    @Override
    public String getManager(int empId)
    {
        try{
            PreparedStatement preparedStatement=connection.prepareStatement(MANAGER_OF_EMPOYEE);
            preparedStatement.setInt(1,empId);
            ResultSet resultSet=preparedStatement.executeQuery();
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
}
