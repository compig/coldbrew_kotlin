package com.compig.init.common.security.exceptions

import com.compig.init.common.exception.GlobalException


class JwtExpiredException private constructor() : GlobalException(SecurityExceptionErrorCode.JWT_EXPIRED) {
    companion object {
        @JvmField
        val EXCEPTION = JwtExpiredException()
    }
}