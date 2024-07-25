package com.study.jwt.jwtpac;

import com.study.jwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

//springsecurity formlogin 부분을 disable처리 후 custom 하여 사용하는 부분
//formlogin 대신 UsernamePasswordAuthenticationFilter 상속받아 구현
public class LoginFiter extends UsernamePasswordAuthenticationFilter {

    private  final AuthenticationManager authenticationManager;
    private final JWTUtill jwtUtill;

    public LoginFiter(AuthenticationManager authenticationManager, JWTUtill jwtUtill) {
        this.authenticationManager = authenticationManager;
        this.jwtUtill = jwtUtill;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username" + username);

        //username과 password를 검증하기 위해서 manager로 보내기 전에
        //UsernamePasswordAuthenticationToken 에 담아서 보내야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authentication){

        //System.out.println("성공");
        //성공후에 jwt 발행
        //user객체 알아내기
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String username = customUserDetails.getUsername();
        //객체 뽑아내기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        //토큰 요청
        String token = jwtUtill.createJwt(username, role, 60*60*1000*10L);
        response.addHeader("Authorization", "Bearer " + token);

    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException faild) {
        response.setStatus(401);

    }


}
