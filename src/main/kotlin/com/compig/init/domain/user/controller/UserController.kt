package com.compig.init.domain.user.controller

import com.compig.init.common.config.logger
import com.compig.init.domain.user.dto.UserSignUp
import com.compig.init.domain.user.dto.UserUpdate
import com.compig.init.domain.user.entity.User
import com.compig.init.domain.user.service.UserService
import lombok.extern.slf4j.Slf4j
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import javax.validation.Valid

@RestController
@Slf4j
@CrossOrigin
class UserController(
    private val userService: UserService,
) {

    @GetMapping("/index")
    private fun getIndexPage(): ResponseEntity<User> {
        logger().info("한글 됨?")
        return ResponseEntity.ok().body(null)
    }

    @PostMapping("/signUp")
    fun signUp(@RequestBody @Valid userSignUpReq: UserSignUp.UserSignUpReq): ResponseEntity<UserSignUp.UserSignUpRep> {
        return ResponseEntity.ok(
            userService.createUser(userSignUpReq)
        )
    }

    @PostMapping("/update")
    fun userUpdate(@RequestBody userUpdateReq: UserUpdate.UserUpdateReq): ResponseEntity<UserUpdate.UserUpdateRep> {
        return ResponseEntity.ok(
            userService.userUpdate(userUpdateReq)
        )
    }
}