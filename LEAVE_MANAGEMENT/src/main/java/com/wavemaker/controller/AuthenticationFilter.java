package com.wavemaker.controller;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebFilter("/*")
public class AuthenticationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        String requestURI = httpRequest.getRequestURI();
        HttpSession session = httpRequest.getSession(false);
        Boolean isLoggedIn = (session != null && session.getAttribute("userId") != null);


        if (requestURI.startsWith(httpRequest.getContextPath() + "/static/") ||
                requestURI.endsWith(".css") || requestURI.endsWith(".js") ||
                requestURI.endsWith(".png") || requestURI.endsWith(".jpg") ||
                requestURI.endsWith(".gif") ||
                requestURI.equals(httpRequest.getContextPath() + "/index.html")) {


            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (isLoggedIn != null && isLoggedIn) {

            filterChain.doFilter(servletRequest, servletResponse);
        } else {

            httpResponse.sendRedirect(httpRequest.getContextPath() + "/index.html");
        }
    }


}