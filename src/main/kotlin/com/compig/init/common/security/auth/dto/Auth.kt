package com.compig.init.common.security.auth.dto

import com.compig.init.common.annotation.NoArg
import javax.validation.constraints.NotBlank

class Auth {
    @NoArg
    data class AuthReq(
        @field:NotBlank
        val userEmail: String,
        @field:NotBlank
        val userPassword: String,
    )
}