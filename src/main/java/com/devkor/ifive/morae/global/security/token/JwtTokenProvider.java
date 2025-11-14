package com.devkor.ifive.morae.global.security.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.devkor.ifive.morae.global.core.properties.JwtProperties;
import com.devkor.ifive.morae.global.exception.JwtAuthException;
import com.devkor.ifive.morae.global.security.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 기반 Access Token 생성 및 검증
 * - HMAC256 알고리즘(대칭키 기반)
 */
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtProperties jwtProperties;

    // JWT(Access Token) 생성
    public String generateToken(Long userId, List<String> userRoles) {
        Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecret());
        Date now = new Date();
        Date expiresAt = new Date(now.getTime() + jwtProperties.getAccessTokenExpiration());

        return JWT.create()
                .withSubject(userId.toString())
                .withClaim("roles", userRoles)
                .withIssuedAt(now)
                .withExpiresAt(expiresAt)
                .sign(algorithm);
    }

    // JWT(Access Token)에서 Authentication 객체 생성
    public Authentication getAuthentication(String token) {
        DecodedJWT decodedJWT = verifyAndDecode(token);

        Long userId = extractUserId(decodedJWT);
        List<String> roles = extractRoles(decodedJWT);

        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        UserPrincipal userPrincipal = new UserPrincipal(userId);
        return new UsernamePasswordAuthenticationToken(userPrincipal, null, authorities);
    }

    // JWT(Access Token) 검증 및 디코딩
    private DecodedJWT verifyAndDecode(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecret());
            return JWT.require(algorithm)
                    .build()
                    .verify(token);
        } catch (TokenExpiredException e) {
            throw new JwtAuthException("토큰이 만료되었습니다.");
        } catch (SignatureVerificationException e) {
            throw new JwtAuthException("토큰 서명 검증에 실패했습니다.");
        } catch (JWTDecodeException e) {
            throw new JwtAuthException("토큰 형식이 올바르지 않습니다.");
        } catch (JWTVerificationException e) {
            throw new JwtAuthException("토큰 검증에 실패했습니다.");
        }
    }

    // JWT(Access Token)에서 userId 추출
    private Long extractUserId(DecodedJWT decodedJWT) {
        String subject = decodedJWT.getSubject();
        try {
            return Long.parseLong(subject);
        } catch (NumberFormatException e) {
            throw new JwtAuthException("토큰의 유저 ID 형식이 올바르지 않습니다.");
        }
    }

    // JWT(Access Token)에서 roles claim 추출
    private List<String> extractRoles(DecodedJWT decodedJWT) {
        List<String> roles = decodedJWT.getClaim("roles").asList(String.class);
        if (roles == null) {
            throw new JwtAuthException("토큰에 권한 정보가 없습니다.");
        }
        return roles;
    }
}