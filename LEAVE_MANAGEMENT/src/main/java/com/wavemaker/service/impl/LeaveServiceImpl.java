package com.wavemaker.service.impl;
import com.wavemaker.models.Leaves;
import com.wavemaker.repository.impl.LeaveRepositoryimpl;
import com.wavemaker.service.LeaveService;
import java.util.HashMap;
import java.util.List;

public class LeaveServiceImpl implements LeaveService {
    private LeaveRepositoryimpl leaveRepositoryimpl;

    public LeaveServiceImpl() {
        leaveRepositoryimpl = new LeaveRepositoryimpl();
    }

    public void applyLeave(Leaves leave) {
        leaveRepositoryimpl.applyLeave(leave);
    }

    public void changeLeaveStatus(Boolean value, int leaveId, int userId) {
        leaveRepositoryimpl.changeLeaveStatus(value, leaveId, userId);
    }

    public Boolean isManager(int userId) {
        return leaveRepositoryimpl.isManager(userId);
    }

    public List<Leaves> getAllLeaves(int userId) {
        return leaveRepositoryimpl.getAllLeaves(userId);
    }

    public List<Leaves> getRequests(int userId) {
        return leaveRepositoryimpl.getRequests(userId);
    }

    @Override
    public HashMap<Leaves.Type, Integer> getTotalCount() {
        return leaveRepositoryimpl.getTotalCount();
    }

    @Override
    public HashMap<Leaves.Type, Integer> getLeaveCount(int userId) {
        return leaveRepositoryimpl.getLeaveCount(userId);
    }
}
