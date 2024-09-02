package com.wavemaker.models;

public class LeaveDTO {
    private int id;

    public enum Type {
        SICK,
        PTO,
        MATERNITY,
        PATERNITY,
        PERSONAL
    }

    ;
    Leaves.Type leaveType;
    private String fromDate;
    private String toDate;
    private String reason;
    Leaves.Status status;
    private String employeeName;

    public LeaveDTO(int id, Leaves.Type leaveType, String fromDate, String toDate, String reason, String employeeName, Leaves.Status status) {
        this.id = id;
        this.leaveType = leaveType;
        this.fromDate = fromDate;
        this.toDate = toDate;
        this.reason = reason;
        this.employeeName = employeeName;
        this.status = status;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public Leaves.Type getLeaveType() {
        return leaveType;
    }

    public void setLeaveType(Leaves.Type leaveType) {
        this.leaveType = leaveType;
    }

    public String getFromDate() {
        return fromDate;
    }

    public void setFromDate(String fromDate) {
        this.fromDate = fromDate;
    }

    public String getToDate() {
        return toDate;
    }

    public void setToDate(String toDate) {
        this.toDate = toDate;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getEmployeeName() {
        return employeeName;
    }

    public void setEmployeeName(String employeeName) {
        this.employeeName = employeeName;
    }
}
