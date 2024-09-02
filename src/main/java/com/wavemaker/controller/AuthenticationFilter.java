package com.wavemaker.controller;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebFilter({"/leave_management/*", "/index.html"})
public class AuthenticationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        boolean cookieValidation = cookieValidation(httpServletRequest);

        if (cookieValidation) {
            chain.doFilter(httpServletRequest, httpServletResponse);
        } else {

            if (!httpServletRequest.getRequestURI().endsWith("index.html")) {
                httpServletResponse.sendRedirect("index.html");
            } else {
                chain.doFilter(httpServletRequest, httpServletResponse);
            }
        }
    }

    private boolean cookieValidation(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = httpServletRequest.getCookies();
        HttpSession session = httpServletRequest.getSession(false);
        if (session != null) {
            Object cookieValue = session.getAttribute("loginCookie");
            if (cookieValue != null && cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("loginCookie") && cookie.getValue().equals(cookieValue.toString())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
