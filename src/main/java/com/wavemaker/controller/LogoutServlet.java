package com.wavemaker.controller;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;

import java.io.IOException;

@WebServlet("/logout")
public class LogoutServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("authToken".equals(cookie.getName())) {
                    // Create a new cookie with the same name and set its max age to zero
                    Cookie cookieToDelete = new Cookie("authToken", null);
                    cookieToDelete.setMaxAge(0);
                    cookieToDelete.setPath(request.getContextPath()); // Make sure this path matches the original path
                    response.addCookie(cookieToDelete);
                    break;
                }
            }
        }
        response.sendRedirect("index.html");
    }

}
