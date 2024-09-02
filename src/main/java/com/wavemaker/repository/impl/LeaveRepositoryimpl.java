package com.wavemaker.repository.impl;

import com.wavemaker.models.Leaves;
import com.wavemaker.repository.LeaveRepository;
import com.wavemaker.utils.DBConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class LeaveRepositoryimpl implements LeaveRepository {

    public static final Logger log = LogManager.getLogger(LeaveRepositoryimpl.class);
    public static final String INSERT_LEAVE = "INSERT INTO LEAVES(EMP_ID,TYPE_ID,FROM_DATE,TO_DATE,STATUS,REASON)VALUES(?,?,?,?,?,?)";
    public static final String GET_LEAVE = "SELECT LEAVES.ID,EMP_ID,TYPE_ID,FROM_DATE," +
            "TO_DATE,STATUS,REASON FROM LEAVES JOIN EMPLOYEE ON LEAVES.EMP_ID=EMPLOYEE.ID WHERE MGR_ID=?";
    public static final String ID_OF_LEAVE = "SELECT ID FROM LEAVE_TYPE WHERE TYPE=?";
    public static final String COUNT_LEAVE = "SELECT SUM(DATEDIFF(TO_DATE,FROM_DATE)+1) AS DIFF FROM LEAVES WHERE EMP_ID=? AND TYPE_ID=? AND STATUS='APPROVED'";
    public static final String LEAVE_TYPE = "SELECT * FROM LEAVE_TYPE";
    public static final String UPDATE_STATUS = "UPDATE LEAVES SET STATUS=? WHERE ID=?";
    public static final String MGRID_EMPLOYEE = "SELECT MGR_ID FROM EMPLOYEE WHERE ID=?";
    public static final String SELECT_LEAVE = "SELECT EMP_ID,TYPE_ID FROM LEAVES WHERE ID=?";
    public static final String EMPLOYEE_OF_MANAGER = "SELECT * FROM EMPLOYEE WHERE MGR_ID=?";
    public static final String LEAVE_EMPLOYEE = "SELECT * FROM LEAVES WHERE EMP_ID=?";
    public static final String LEAVETYPE_OF_ID = "SELECT TYPE FROM LEAVE_TYPE WHERE ID=?";
    Connection connection;


    public LeaveRepositoryimpl() {
        connection = DBConnection.getConnection();
    }

    @Override
    public void applyLeave(Leaves leave) {
        try {
            PreparedStatement ps = connection.prepareStatement(ID_OF_LEAVE);
            ps.setString(1, leave.getType().name());
            ResultSet rs = ps.executeQuery();
            int id = 1;
            if (rs.next()) {
                id = rs.getInt(1);
            }
            ps = connection.prepareStatement(INSERT_LEAVE);
            ps.setInt(1, leave.getEmpId());
            ps.setString(3, leave.getFromDate());
            ps.setString(4, leave.getToDate());
            ps.setString(5, leave.getStatus().name());
            ps.setString(6, leave.getReason());
            ps.setInt(2, id);
            ps.executeUpdate();
            log.info("Leave " + leave.getEmpId() + " successfully applied");
        } catch (Exception e) {
            log.error(e);
        }

    }

    @Override
    public void changeLeaveStatus(Boolean value, int leaveId, int userId) {
        try {

            PreparedStatement ps = connection.prepareStatement(SELECT_LEAVE);
            ps.setInt(1, leaveId);
            ResultSet rs = ps.executeQuery();
            int emp_id = -1, mgrId = -1;
            rs.next();
            emp_id = rs.getInt("EMP_ID");
            int typeId = rs.getInt("TYPE_ID");

            ps = connection.prepareStatement(MGRID_EMPLOYEE);
            ps.setInt(1, emp_id);
            rs = ps.executeQuery();
            if (rs.next()) {
                mgrId = rs.getInt("MGR_ID");
            }
            if (mgrId == userId) {
                ps = connection.prepareStatement(UPDATE_STATUS);
                if (value) {
                    ps.setString(1, "APPROVED");
                } else {
                    ps.setString(1, "REJECTED");
                }

                ps.setInt(2, leaveId);
                ps.executeUpdate();
                log.info("leave status changed");
            } else {
                log.info("you are not allowed to change leave status");
            }
        } catch (SQLException e) {
            log.error(e);
        }

    }

    @Override
    public Boolean isManager(int userId) {
        try {
            PreparedStatement ps = connection.prepareStatement(EMPLOYEE_OF_MANAGER);
            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            log.error(e);
        }
        return false;
    }


    @Override
    public List<Leaves> getAllLeaves(int userId) {
        try {
            PreparedStatement ps = connection.prepareStatement(LEAVE_EMPLOYEE);
            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();

            List<Leaves> leaves = new ArrayList<Leaves>();
            while (rs.next()) {
                PreparedStatement ps1 = connection.prepareStatement(LEAVETYPE_OF_ID);
                ps1.setInt(1, rs.getInt("TYPE_ID"));
                ResultSet rs1 = ps1.executeQuery();
                Leaves.Type type;
                rs1.next();
                type = Leaves.Type.valueOf(rs1.getString("TYPE"));
                Leaves leave = new Leaves(userId,
                        type,
                        rs.getString("FROM_DATE"), rs.getString("TO_DATE"),
                        rs.getString("REASON"),
                        Leaves.Status.valueOf(rs.getString("STATUS")));
                leave.setId(rs.getInt("ID"));
                leaves.add(leave);
            }
            return leaves;
        } catch (SQLException e) {
            log.error(e);
            log.info("get leave error");
        }
        return null;
    }

    @Override
    public List<Leaves> getRequests(int userId) {
        try {
            PreparedStatement ps = connection.prepareStatement(GET_LEAVE);
            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();
            List<Leaves> leaves = new ArrayList<Leaves>();
            while (rs.next()) {
                PreparedStatement ps1 = connection.prepareStatement(LEAVETYPE_OF_ID);
                ps1.setInt(1, rs.getInt("TYPE_ID"));
                ResultSet rs1 = ps1.executeQuery();
                Leaves.Type type;
                rs1.next();
                type = Leaves.Type.valueOf(rs1.getString("TYPE"));
                Leaves leave = new Leaves(rs.getInt("EMP_ID"),
                        type,
                        rs.getString("FROM_DATE"), rs.getString("TO_DATE"),
                        rs.getString("REASON"),
                        Leaves.Status.valueOf(rs.getString("STATUS")));
                leave.setId(rs.getInt("ID"));
                leaves.add(leave);
            }
            return leaves;

        } catch (SQLException E) {
            log.error(E);
            log.info("get request error");
        }
        return null;
    }

    @Override
    public HashMap<Leaves.Type, Integer> getTotalCount() {
        HashMap<Leaves.Type, Integer> map = new HashMap<>();
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(LEAVE_TYPE);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                map.put(Leaves.Type.valueOf(rs.getString("TYPE")), rs.getInt("COUNT"));
            }
        } catch (SQLException E) {
            log.error(E);
        }
        return map;
    }

    @Override
    public HashMap<Leaves.Type, Integer> getLeaveCount(int userId) {
        HashMap<Leaves.Type, Integer> map = new HashMap<>();
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(LEAVE_TYPE);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                int type_id = resultSet.getInt("ID");
                String type = resultSet.getString("TYPE");
                PreparedStatement ps = connection.prepareStatement(COUNT_LEAVE);
                ps.setInt(1, userId);
                ps.setInt(2, type_id);
                ResultSet rs = ps.executeQuery();
                rs.next();
                map.put(Leaves.Type.valueOf(type), rs.getInt("DIFF"));
            }
        } catch (SQLException E) {
            log.error(E);
        }
        return map;
    }

}
