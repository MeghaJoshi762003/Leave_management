package com.wavemaker.controller;

import com.google.gson.Gson;
import com.wavemaker.models.Leaves;
import com.wavemaker.service.EmployeeService;
import com.wavemaker.service.LeaveService;
import com.wavemaker.service.LoginService;
import com.wavemaker.service.impl.EmployeeServiceImpl;
import com.wavemaker.service.impl.LeaveServiceImpl;
import com.wavemaker.service.impl.LoginServiceImpl;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;
import java.util.Properties;

@WebServlet("/employee")
public class LeavesServlet extends HttpServlet {
    private static final Logger log = LogManager.getLogger(LeavesServlet.class);
    private static LoginService loginService;
    private static LeaveService leaveService;
    private static EmployeeService employeeService;

    public LeavesServlet() {
        loginService = new LoginServiceImpl();
        leaveService = new LeaveServiceImpl();
        employeeService = new EmployeeServiceImpl();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession(false);
        int userId = Integer.parseInt(session.getAttribute("userId").toString());
        String email = session.getAttribute("email").toString();

        if (loginService.validateUser(userId, email)) {
            List<Leaves> leaves = leaveService.getAllLeaves(userId);
            Gson gson = new Gson();
            String json = gson.toJson(leaves);
            resp.setContentType("application/json");
            resp.getWriter().write(json);
        } else {
            log.info("invalid credentials");
            resp.sendRedirect(req.getContextPath() + "/login");
        }

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession(false);
        int userId = Integer.parseInt(session.getAttribute("userId").toString());
        String email = (String) session.getAttribute("email");
        if (loginService.validateUser(userId, email)) {
            Leaves.Type type = Leaves.Type.valueOf(req.getParameter("type"));
            log.info(type.toString());
            String fdate = req.getParameter("fdate");
            log.info(fdate);
            String tdate = req.getParameter("tdate");
            log.info(tdate);
            String reason = req.getParameter("reason");
            log.info(reason);
            Leaves.Status status = Leaves.Status.valueOf("PENDING");
            log.info(status.toString());
            Leaves leave = new Leaves(userId, type, fdate, tdate, reason, status);
            leaveService.applyLeave(leave);
            log.info(leave.toString());

//            String to = employeeService.getManagerEmail(userId);
//            String subject = "Leave Application";
//            String body = "Hello, Please Accept my leave application from date" + fdate + " todate" + tdate;

//            final String host = "smtp.gmail.com";
//            final String user = email;
//            final String password = employeeService.getPassword(user);
//
//
//            Properties properties = new Properties();
//            properties.put("mail.smtp.host", host);
//            properties.put("mail.smtp.port", "587");
//            properties.put("mail.smtp.auth", "true");
//            properties.put("mail.smtp.starttls.enable", "true");
//
//            Session sess = Session.getInstance(properties, new Authenticator() {
//                @Override
//                protected PasswordAuthentication getPasswordAuthentication() {
//                    return new PasswordAuthentication(user, password);
//                }
//            });
//
//            try {
//                MimeMessage message = new MimeMessage(sess);
//                message.setFrom(new InternetAddress(user));
//                message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
//                message.setSubject(subject);
//                message.setText(body);
//                // Send message
//                Transport.send(message);
//                log.info("email sent successfully");
//            } catch (MessagingException mex) {
//                mex.printStackTrace();
//                log.info("Error sending email: " + mex.getMessage());
//            }

            resp.sendRedirect(req.getContextPath() + "/main.html");
        } else {
            log.info("invalid credentials");
            resp.sendRedirect(req.getContextPath() + "/index.html");
        }

    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession(false);
        int userId = Integer.parseInt(session.getAttribute("userId").toString());
        String email = (String) session.getAttribute("email");
        if (loginService.validateUser(userId, email)) {
            Boolean value = req.getParameter("value").equals("true");
            int leaveId = Integer.parseInt(req.getParameter("id"));
            leaveService.changeLeaveStatus(value, leaveId, userId);
            log.info("status updated");
        } else {
            log.info("invalid credentials");
            resp.sendRedirect(req.getContextPath() + "/login");
        }
    }

}
