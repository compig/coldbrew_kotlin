package com.compig.init.common.security.jwt

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest

/**
 * JwtTokenProvider를 이용해 헤더에서 JWT를 받아와 유효한 토큰인지 확인
 * 유효할 경우 유저 정보를 SecurityContextHolder에 저장하는 역할
 * **/
class JwtAuthenticationFilter(private val jwtTokenProvider: JwtTokenProvider) : GenericFilterBean() {

    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        // 헤더에서 JWT 를 받아옵니다.
        val jwToken: String? = jwtTokenProvider.getTokenFromHeader((request as HttpServletRequest))
        // 유효한 토큰인지 확인합니다.
        jwToken?.let {
            val token: String = jwtTokenProvider.validationJwt(it)
            val authentication = jwtTokenProvider.authenticateUser(token)
            // SecurityContext 에 Authentication 객체를 저장합니다.
            SecurityContextHolder.getContext().authentication = authentication
        }
        chain.doFilter(request, response)
    }

}