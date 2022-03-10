package com.compig.init.common.security.auth.dto

import com.compig.init.common.annotation.NoArg

class AccessToken {
    @NoArg
    data class AccessTokenRep(
        val accessToken: String,
    )
}