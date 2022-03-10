package com.compig.init.common.security.exceptions

import com.compig.init.common.exception.ExceptionProperty
import org.springframework.http.HttpStatus

enum class SecurityExceptionErrorCode(
    override val serverMessage: String,
    override val clientMessage: String,
    override val httpStatus: HttpStatus,
) :
    ExceptionProperty {
    NOT_FOUND_USER_EMAIL("not found user Email.", "아이디가 없습니다.", HttpStatus.BAD_REQUEST),
    JWT_EXPIRED("Jwt Token Expired", "토큰이 만료되었습니다.", HttpStatus.UNAUTHORIZED)
}