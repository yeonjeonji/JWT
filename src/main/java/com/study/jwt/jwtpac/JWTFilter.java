package com.study.jwt.jwtpac;

import com.study.jwt.dto.CustomUserDetails;
import com.study.jwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtill jwtUtill;

    public JWTFilter(JWTUtill jwtUtill) {
        this.jwtUtill = jwtUtill;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //request에서 Authorization헤더를 찾음
        String authorization = request.getHeader("Authorization");

        //Authorization headerrjawmd
        if(authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");

            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료(필수)
            return;
        }

        String token = authorization.split(" ")[1];

        if (jwtUtill.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료(필수)
            return;
        }

        String username = jwtUtill.getUsername(token);
        String role = jwtUtill.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken
        (customUserDetails, null, customUserDetails.getAuthorities());
        //세션에 사용자 등록

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
