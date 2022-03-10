package com.compig.init.controller

import com.compig.init.domain.user.dto.UserSignUp
import com.compig.init.domain.user.dto.UserUpdate
import com.compig.init.domain.user.enumm.UserStatus
import com.google.gson.Gson
import org.junit.jupiter.api.*
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@ExtendWith(SpringExtension::class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
@ActiveProfiles("test")
@AutoConfigureMockMvc
//@Transactional
internal class UserControllerTest(
    @Autowired private val mockMvc: MockMvc,
    @Autowired private val gson: Gson,
) {

    @AfterEach
    fun tearDown() {

    }

    @Test
    @Order(1)
    fun signUp() {
        val request = UserSignUp.UserSignUpReq(userEmail = "",
            userPassword = "1234",
            regUserId = 1L,
            userStatus = UserStatus.USE)
        mockMvc.perform(
            post("/signUp")
                .content(gson.toJson(request))
                .contentType(MediaType.APPLICATION_JSON)
        )
            //기대하는 응답코드
            .andExpect(status().isOk)
            //기대하는 결과값
            //.andExpect(content().string("{}"))
            //결과 출력
            .andDo(print())
    }

    @Test
    @Order(2)
    fun login() {
        val request = UserLogin.UserLoginReq(
            userEmail = "compig",
            userPassword = "1234")
        mockMvc.perform(
            post("/login")
                .content(gson.toJson(request))
                .contentType(MediaType.APPLICATION_JSON)
        )
            //기대하는 응답코드
            .andExpect(status().isOk)
            //기대하는 결과값
            //.andExpect(content().string("{}"))
            //결과 출력
            .andDo(print())
    }

    @Test
    fun userUpdate() {
        val request = UserUpdate.UserUpdateReq(
            userEmail = "compig",
            userLastName = "com",
            userFirstName = "pig",
            userPassword = "1234",
            userBirth = "0000",
            userSex = "F",
            modifyUserId = 1L,
            modifyIp = "aa",
        )
        mockMvc.perform(
            post("/update")
                .content(gson.toJson(request))
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization",
                    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjb21waWcxIiwidXNlclBrIjoiY29tcGlnMSIsImlhdCI6MTY0NDk0MjYzMCwiZXhwIjoxNjQ0OTQ0NDMwfQ.M44I0HZSN02n7RfQOBcXz3Xb-SNnvf1vM5b22LbhsSU")
        )
            //기대하는 응답코드
            .andExpect(status().isOk)
            //기대하는 결과값
            //.andExpect(content().string("{}"))
            //결과 출력
            .andDo(print())
    }

}