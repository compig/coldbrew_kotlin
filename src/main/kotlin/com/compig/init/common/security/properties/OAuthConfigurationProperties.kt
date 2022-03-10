package com.compig.init.common.security.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding

@ConstructorBinding
@ConfigurationProperties(prefix = "spring.security.oauth2.client.provider")
class OAuthConfigurationProperties(
    val clientId: String,
    // JWT를 생성하고 검증하는 컴포넌트
    //secretKey 글자가 작으면 에러남
    val secretKey: String,
    val accessTokenValiditySeconds: Long,
    val refreshTokenValiditySeconds: Long,
){
    companion object {
        const val TOKEN_PREFIX = "Bearer "
        const val TOKEN_HEADER_NAME = "Authorization"
        const val ACCESS_VALUE = "access"
        const val REFRESH_VALUE = "refresh"
    }
}