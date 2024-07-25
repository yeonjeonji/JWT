package com.study.jwt.config;

import com.study.jwt.jwtpac.JWTFilter;
import com.study.jwt.jwtpac.JWTUtill;
import com.study.jwt.jwtpac.LoginFiter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //Manager에 변수로 보내기 위함
    private final  AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtill jwtUtill;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtill jwtUtill) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtill = jwtUtill;
    }


    //해시암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return  configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//        http
//                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
//
//                    @Override
//                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//
//                        CorsConfiguration configuration = new CorsConfiguration();
//
//                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
//                        configuration.setAllowedMethods(Collections.singletonList("*"));
//                        configuration.setAllowCredentials(true);
//                        configuration.setAllowedHeaders(Collections.singletonList("*"));
//                        configuration.setMaxAge(3600L);
//
//                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));
//
//                        return configuration;
//                    }
//                })));

        //세션방식에서는 세션이 고정이 되기때문에 필수 방어
        //jwt방식은 스테이스리스방식으로 방어하지 않아도 되기때문에 막아둠
        http
                .csrf((auth) -> auth.disable());

        //jwt방식으로 로그인할거기 때문에 막아둠
        http
                .formLogin((auth) -> auth.disable());
        http
                .httpBasic((auth) -> auth.disable());


        //join경로는 전체 접근 가능
        //admin만 가능
        //authenticated() 로그인한 사용자만 접근가능한 메소드
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());
        http
                .addFilterBefore(new JWTFilter(jwtUtill), LoginFiter.class);

        //LoginFilter를 사용할 수 있도록 등록하는 부분
        http
                .addFilterAt(new LoginFiter(authenticationManager(authenticationConfiguration), jwtUtill), UsernamePasswordAuthenticationFilter.class);

        //세션 설정
        //JWT에서는 항상 session stateless 상태로 진행
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
