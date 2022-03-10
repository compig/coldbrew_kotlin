package com.compig.init.common.security.auth.controller

import com.compig.init.common.security.auth.dto.Auth
import com.compig.init.common.security.auth.dto.Token
import com.compig.init.domain.user.service.AuthService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import javax.validation.Valid

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authService: AuthService
) {
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun signIn(@RequestBody @Valid authRequest: AuthRequest): BaseResponse<Token> {
        return authService.signIn(authRequest)
    }

    @PostMapping("/login")//TODO controller 따로 빼기
    fun signUp(@RequestBody auth: Auth.AuthReq): ResponseEntity<Token.TokenRep> {
        return ResponseEntity.ok(
            authService.signIn(auth)
        )
    }

    @PutMapping
    fun refreshToken(@RequestHeader("Refresh-Token") refreshToken: String): BaseResponse<AccessTokenResponse> {
        return authService.tokenRefresh(refreshToken)
    }

}