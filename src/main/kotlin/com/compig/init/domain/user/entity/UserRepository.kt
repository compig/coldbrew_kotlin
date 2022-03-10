package com.compig.init.domain.user.entity

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : JpaRepository<User, Long?> {

    fun findByUserSeqId(userSeqId: Long): User?

    fun findByUserEmail(userEmail: String): User?

    @Query(nativeQuery = true, value = "SELECT auth.AUTH_NAME AS authName" +
            " FROM TAUTH auth" +
            " LEFT JOIN TAUTH_MEMBER authMember ON authMember.AUTH_SEQ_ID = auth.AUTH_SEQ_ID" +
            " LEFT JOIN TSERVICE service ON service.SERVICE_SEQ_ID = auth.SERVICE_SEQ_ID" +
            " WHERE authMember.AUTH_MEMBER_SEQ_ID = :userSeqId")
    fun findRoleByUserSeqId(@Param("userSeqId") userSeqId: Long): List<String>
}
