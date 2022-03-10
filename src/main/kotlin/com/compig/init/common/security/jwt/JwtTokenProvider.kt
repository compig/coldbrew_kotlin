package com.compig.init.common.security.jwt

import com.compig.init.common.security.auth.AuthDetailsService
import com.compig.init.common.security.exceptions.JwtExpiredException
import com.compig.init.common.security.properties.OAuthConfigurationProperties
import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import java.util.*
import javax.annotation.PostConstruct
import javax.crypto.SecretKey
import javax.servlet.http.HttpServletRequest

/**
 * JWT 토큰을 발급하고, 인증 정보를 조회하고, 회원 정보를 추출
 * https://codingdiary99.tistory.com/entry/Spring-boot-Kotlin-Spring-security-JWT-%EB%A1%9C%EA%B7%B8%EC%9D%B8-%EA%B5%AC%ED%98%84%ED%95%98%EA%B8%B0
 * https://samtao.tistory.com/65
 * **/
@Component
//@Qualifier - Spring이 어떤 bean을 주입할지 모름 명시해줌
class JwtTokenProvider(
    @Qualifier("authDetailsService") private val authDetailsService: AuthDetailsService,
    private val oAuthConfigurationProperties: OAuthConfigurationProperties,
) {
    // 객체 초기화, secretKey를 Base64로 인코딩한다.
    lateinit var key: SecretKey

    //lateinit - var(mutable)에서만 사용이 가능
    @PostConstruct //web server 가 올라갈때 초기화 된다.
    protected fun init() {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(oAuthConfigurationProperties.secretKey));
    }

    // JWT 토큰 생성
    private fun generateToken(userPk: String, expiration: Long, type: String): String {
        return "Bearer " + Jwts.builder()
            .setHeaderParam("typ", type)
            .setSubject(userPk)
            .setIssuedAt(Date())
            .signWith(key, SignatureAlgorithm.HS256) // 사용할 암호화 알고리즘과 signature 에 들어갈 secret 값 세팅
            .setExpiration(Date(System.currentTimeMillis() + expiration * 1000))
            .compact()
    }

    fun authenticateUser(token: String): Authentication {
        val claims = getClaims(token)
        val id = claims.subject
        val authDetails = authDetailsService.loadUserByUsername(id.toString())
        return UsernamePasswordAuthenticationToken(authDetails, "", authDetails.authorities)
    }

    // Request의 Header에서 token 값을 가져옵니다. "X-AUTH-TOKEN" : "TOKEN값'
    fun getTokenFromHeader(httpServletRequest: HttpServletRequest): String? =
        httpServletRequest.getHeader(OAuthConfigurationProperties.TOKEN_HEADER_NAME)

    fun validationJwt(token: String): String {
        if (token.startsWith(OAuthConfigurationProperties.TOKEN_PREFIX)) {
            return token.replace(OAuthConfigurationProperties.TOKEN_PREFIX, "")
        }
        throw JwtExpiredException.EXCEPTION
    }

    // 토큰의 유효성 + 만료일자 확인
    // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
    // JWT 토큰에서 인증 정보 조회
    fun getClaims(jwtToken: String): Claims {
        return try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwtToken).body
        } catch (e: Exception) {
            when (e) {
                is ExpiredJwtException -> throw JwtExpiredException.EXCEPTION
                else -> throw JwtExpiredException.EXCEPTION
            }
        }
    }
}