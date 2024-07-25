package com.study.jwt.jwtpac;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.EncryptionKey;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Date;

@Component
public class JWTUtill {

    private SecretKey secretKey;

    public JWTUtill(@Value("${spring.jwt.securitypass}")String securitypass) {
        this.secretKey = new SecretKeySpec(securitypass.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build()
                .getAlgorithm());

    }

    //검증
    public String getUsername(String token) {
        //우리서버에서 생성된게 맞는지 검증
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().
                get("username", String.class);
    }

    public String getRole(String token) {
        //우리서버에서 생성된게 맞는지 검증
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().
                get("role", String.class);
    }

    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }
    //token생성

    public String createJwt(String username, String role, Long expiredMs) {

        return Jwts.builder()
                //페이로드 부분
                .claim("username", username)
                .claim("role", role)
                //현재발행시간
                .issuedAt(new Date(System.currentTimeMillis()))
                //언제소멸될것인지
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                //암호화진행
                .signWith(secretKey)
                //토큰 compact
                .compact();
    }
}
