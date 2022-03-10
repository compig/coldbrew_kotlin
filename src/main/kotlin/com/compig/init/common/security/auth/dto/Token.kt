package com.compig.init.common.security.auth.dto

import com.compig.init.common.annotation.NoArg

class Token {
    @NoArg
    data class TokenRep(
        val accessToken: String,
        val refreshToken: String,
    )
}