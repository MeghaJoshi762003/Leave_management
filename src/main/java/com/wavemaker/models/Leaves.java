package com.wavemaker.models;
public class Leaves {
    private int id;
    private int empId;

    public enum Type {
        SICK,
        PTO,
        MATERNITY,
        PATERNITY,
        PERSONAL
    }

    ;
    Type leaveType;
    private String fromDate;
    private String toDate;
    private String reason;

    public enum Status {
        PENDING,
        REJECTED,
        APPROVED,
    }

    ;
    Status status;

    public Leaves(int empId, Type type, String fromDate, String toDate, String reason, Status status) {
        this.empId = empId;
        this.leaveType = type;
        this.fromDate = fromDate;
        this.toDate = toDate;
        this.reason = reason;
        this.status = status;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getEmpId() {
        return empId;
    }

    public void setEmpId(int empId) {
        this.empId = empId;
    }

    public Type getType() {
        return leaveType;
    }

    public void setType(Type type) {
        this.leaveType = type;
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

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }
}
