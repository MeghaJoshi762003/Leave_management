package com.wavemaker.repository;

import com.wavemaker.models.Employee;
import com.wavemaker.models.Leaves;

import java.util.HashMap;
import java.util.List;

public interface LeaveRepository {
    void applyLeave(Leaves leave);
    void changeLeaveStatus(Boolean value,int leaveId,int userId);
    Boolean isManager(int userId);
    List<Leaves> getAllLeaves(int userId);
    List<Leaves> getRequests(int userId);
    HashMap<Leaves.Type,Integer> getTotalCount();
    HashMap<Leaves.Type,Integer> getLeaveCount(int userId);
    }
