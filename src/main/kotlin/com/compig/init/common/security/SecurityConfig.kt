package com.compig.init.common.security

import com.compig.init.common.security.auth.AuthDetailsService
import com.compig.init.common.security.jwt.JwtAuthenticationFilter
import com.compig.init.common.security.jwt.JwtTokenProvider
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration

/**
 * passwordEncoder를 만들고, 앞에서 만들어준 JwtAuthenticationFilter를 등록
 *로그인과 회원가입 요청 Url을 제외한 나머지는 인증을 받아야 요청 가능하도록 권한을 설정
 * **/
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
class SecurityConfig(
    private val jwtTokenProvider: JwtTokenProvider,
    private val authDetailsService: AuthDetailsService,
) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http.httpBasic().disable() //REST API만 고려, 기본 설정해제
            .csrf().disable() //csrf 보안토큰 disable 처리
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //토큰 기반 인증이므로 세션 사용 안함
            .and()
            .authorizeRequests()//요청에 대한 사용권한 체크
            .antMatchers("/api/**").authenticated()
            .antMatchers(
                "/index",
                "/signUp",
                "/login/**",
                "/logout/**"
            ).permitAll()//로그인, 회원가입은 누구나 접근 가능
            .and()
            .formLogin(
                Customizer.withDefaults()
            )
            .cors {
                it.configurationSource {
                    val configuration = CorsConfiguration()
                    configuration.allowCredentials = true
                    configuration.allowedOrigins = listOf("http://localhost:13001")
                    configuration.allowedMethods = listOf("GET", "POST", "PATCH", "DELETE", "OPTIONS")
                    configuration.maxAge = 3600
                    configuration
                }
            }.addFilterBefore(
                JwtAuthenticationFilter(jwtTokenProvider),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .oauth2ResourceServer()
            .jwt()
    }

    @Bean
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(authDetailsService)
            .passwordEncoder(this.passwordEncoder())
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

}