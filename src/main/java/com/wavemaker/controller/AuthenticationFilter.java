package com.wavemaker.controller;

import com.wavemaker.service.TokenService;
import com.wavemaker.service.impl.TokenServiceImpl;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebFilter({"/leave_management/*", "/index.html"})
public class AuthenticationFilter implements Filter {

    private static TokenService tokenService;
    public AuthenticationFilter() {
        tokenService=new TokenServiceImpl();
    }
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

    private boolean cookieValidation(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        Cookie authCookie = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("authToken".equals(cookie.getName())) {
                    authCookie = cookie;
                    break;
                }
            }
        }
        if (authCookie != null) {
            String token = authCookie.getValue();
            // Validate the token (e.g., check if it exists in the database or matches a known pattern)
            int isValid = tokenService.validateToken(token);

            if (isValid!=-1) {
               return true;
            } else {
                return false;
            }
        } else {
           return false;
        }


    }
}
