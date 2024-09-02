package com.wavemaker.controller;
import com.wavemaker.models.Employee;
import com.wavemaker.service.EmployeeService;
import com.wavemaker.service.LeaveService;
import com.wavemaker.service.TokenService;
import com.wavemaker.service.impl.EmployeeServiceImpl;
import com.wavemaker.service.impl.LeaveServiceImpl;
import com.wavemaker.service.LoginService;
import com.wavemaker.service.impl.LoginServiceImpl;
import com.wavemaker.service.impl.TokenServiceImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private static final Logger log = LogManager.getLogger(LoginServlet.class);
    private final TokenService tokenService;
    private final LoginService loginService;
    private final LeaveService leaveService;
    private final EmployeeService employeeService;

    public LoginServlet() {
        loginService = new LoginServiceImpl();
        leaveService = new LeaveServiceImpl();
        employeeService = new EmployeeServiceImpl();
        tokenService = new TokenServiceImpl();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String email = req.getParameter("email");
        String password = req.getParameter("password");
        int userId = loginService.authenticate(email, password);
        if (userId != -1) {
            String token = tokenService.generateToken(userId);

            Cookie authCookie = new Cookie("authToken", token);
            authCookie.setMaxAge(60 * 60 * 24 * 7);
            authCookie.setHttpOnly(true);
            authCookie.setPath(req.getContextPath());
            resp.addCookie(authCookie);

            HttpSession session = req.getSession(true);
            session.setAttribute("userId", userId);
            session.setAttribute("email", email);
            Employee employee;
            employee = employeeService.getEmployee(userId);
            req.setAttribute("username", employee.getName());
            log.info("logged in");
            resp.sendRedirect(req.getContextPath() + "/main.html");
        } else {
            log.info("invalid credentials");
            resp.sendRedirect(req.getContextPath() + "/index.html");
        }

    }
}
