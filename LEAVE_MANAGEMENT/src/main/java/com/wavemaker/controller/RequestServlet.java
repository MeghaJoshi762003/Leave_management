package com.wavemaker.controller;
import com.google.gson.Gson;
import com.wavemaker.models.Employee;
import com.wavemaker.models.EmployeeDTO;
import com.wavemaker.models.LeaveDTO;
import com.wavemaker.models.Leaves;
import com.wavemaker.service.EmployeeService;
import com.wavemaker.service.LeaveService;
import com.wavemaker.service.LoginService;
import com.wavemaker.service.impl.EmployeeServiceImpl;
import com.wavemaker.service.impl.LeaveServiceImpl;
import com.wavemaker.service.impl.LoginServiceImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@WebServlet("/request")
public class RequestServlet extends HttpServlet {
    private static final Logger log = LogManager.getLogger(LeavesServlet.class);
    private static LoginService loginService;
    private static LeaveService leaveService;
    private static EmployeeService employeeService;
    public RequestServlet() {
        loginService = new LoginServiceImpl();
        leaveService = new LeaveServiceImpl();
        employeeService = new EmployeeServiceImpl();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession(false);
        int userId=Integer.parseInt(session.getAttribute("userId").toString());
        String email=session.getAttribute("email").toString();
        if(loginService.validateUser(userId, email)) {
            Employee employee=employeeService.getEmployee(userId);
//            getting request that will come to manager
            List<Leaves> leaves= leaveService.getRequests(userId);
            List<LeaveDTO> leavesDTO=new ArrayList<>();
            if(leaves!=null) {
                for(Leaves leave:leaves) {

                    String name= employeeService.getEmployee(leave.getEmpId()).getName();
                    LeaveDTO leaveDTO=new LeaveDTO(leave.getId(),leave.getType(), leave.getFromDate(),
                            leave.getToDate(), leave.getReason(),name ,leave.getStatus());
                    leavesDTO.add(leaveDTO);
                }
            }
            HashMap<Leaves.Type,Integer> total_count=leaveService.getTotalCount();
            HashMap<Leaves.Type,Integer> leave_taken=leaveService.getLeaveCount(userId);

            List<Employee> employees=new ArrayList<>();

            List<EmployeeDTO> employeeDTO=new ArrayList<>();
//            getting employee that are under that manager
            employees=employeeService.getAllEmployeesOfManager(userId);
            Map<Integer,Map<Leaves.Type,Integer>> empLeaves=new HashMap<>();
            for(Employee emp:employees)
            {
                empLeaves.put(emp.getId(),leaveService.getLeaveCount(emp.getId()));
            }
            if(employees!=null) {
                for(Employee emp:employees) {
                    EmployeeDTO employeeDTO1=new EmployeeDTO(emp.getName(),emp.getPhoneNumber(),emp.getGender(),emp.getId());
                    employeeDTO.add(employeeDTO1);
                }
            }
            Map<String, Object> responseMap = new HashMap<>();
            responseMap.put("leaves", leavesDTO);
            responseMap.put("employees", employeeDTO);
            responseMap.put("emp", employee);
            responseMap.put("total_count", total_count);
            responseMap.put("leave_taken", leave_taken);
            responseMap.put("email",email);
            responseMap.put("empleaves", empLeaves);
            Gson gson=new Gson();
            String json=gson.toJson(responseMap);
            resp.setContentType("application/json");
            resp.getWriter().write(json);
        }
        else{
            log.info("invalid credentials");
            resp.sendRedirect(req.getContextPath()+"/login");
        }
    }
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession(false);
        int userId=Integer.parseInt(session.getAttribute("userId").toString());
        String email=session.getAttribute("email").toString();
        if(loginService.validateUser(userId, email)) {
            Boolean status=req.getParameter("status").equals("true");
            int leaveId=Integer.parseInt(req.getParameter("leaveId").toString());
            leaveService.changeLeaveStatus(status, leaveId, userId);
        }
        else{
            log.info("invalid credentials");
            resp.sendRedirect(req.getContextPath()+"/login");
        }
    }
}
