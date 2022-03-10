package com.compig.init.common.security.auth

import com.compig.init.common.config.logger
import com.compig.init.common.security.exceptions.UserNotFoundException
import com.compig.init.domain.user.entity.User
import com.compig.init.domain.user.entity.UserRepository
import com.google.gson.Gson
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

//TODO oauth2 적용
@Service
class AuthDetailsService(private val userRepository: UserRepository, private val gson: Gson) :
    UserDetailsService {
    override fun loadUserByUsername(userEmail: String): UserDetails {
        logger().info("로그인 시도 : '{}'", userEmail)
        val user: User = userRepository.findByUserEmail(userEmail)
            ?: throw UserNotFoundException.EXCEPTION
        logger().info("로그인 유저 정보 : {}", gson.toJson(user))
        return AuthDetails(user = user, authorities(user))
    }

    private fun authorities(user: User): MutableCollection<out GrantedAuthority> {
        val roleNames: List<String> = userRepository.findRoleByUserSeqId(user.userSeqId)
        val authorityList: MutableCollection<GrantedAuthority> = mutableListOf()
        for (roleName in roleNames) {
            authorityList.add(SimpleGrantedAuthority(roleName))
        }
        return authorityList
    }

}