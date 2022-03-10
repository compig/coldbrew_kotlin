package com.compig.init

import com.compig.init.common.security.properties.OAuthConfigurationProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import org.springframework.data.jpa.repository.config.EnableJpaAuditing

@EnableJpaAuditing
@SpringBootApplication
@EnableConfigurationProperties(value = [OAuthConfigurationProperties::class])
class InitApplication

fun main(args: Array<String>) {
    runApplication<InitApplication>(*args)
}
