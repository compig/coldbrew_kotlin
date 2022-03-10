package com.compig.init.domain.user.service

import com.compig.init.common.security.auth.dto.Auth
import com.compig.init.common.security.auth.dto.Token
import com.compig.init.common.security.jwt.JwtTokenProvider
import com.compig.init.domain.user.entity.User
import com.compig.init.domain.user.entity.UserRepository
import com.compig.init.domain.user.exceptions.NotFoundUserEmailException
import org.modelmapper.ModelMapper
import org.springframework.dao.InvalidDataAccessApiUsageException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import javax.transaction.Transactional

@Service
@Transactional
class AuthService(
    private val passwordEncoder: PasswordEncoder,
    private val userRepository: UserRepository,
    private val jwtTokenProvider: JwtTokenProvider,

    ) {

    fun existUser(userEmail: String): Boolean {
        userRepository.findByUserEmail(userEmail)?.let {
            return true
        } ?: return false
    }

    fun findUser(userEmail: String): User {
        return userRepository.findByUserEmail(userEmail) ?: throw NullPointerException("user not found.")
    }

    fun signIn(auth: Auth.AuthReq): Token.TokenRep {
        if (!existUser(auth.userEmail)) {
            throw NotFoundUserEmailException.EXCEPTION
        }
        val user: User = findUser(auth.userEmail)

        if (!passwordEncoder.matches(auth.userPassword, user.password)) {
            throw InvalidDataAccessApiUsageException("invalid password.")
        }

        return Token.TokenRep(
            accessToken = jwtTokenProvider.createToken(user.userEmail), user)
        refreshToken =
    }

}