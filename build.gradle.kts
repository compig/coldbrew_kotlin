import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "2.6.2"
    id("io.spring.dependency-management") version "1.0.11.RELEASE"
    kotlin("jvm") version "1.6.0"
    kotlin("plugin.spring") version "1.6.0"
    kotlin("plugin.jpa") version "1.6.0"
    kotlin("plugin.allopen") version "1.6.0"
    kotlin("kapt") version "1.5.30"
}

noArg {
    annotation("javax.persistence.Entity")
    annotation("javax.persistence.MappedSuperclass")
    annotation("javax.persistence.Embeddable")
    annotation("com.compig.init.common.annotation.NoArg")
    invokeInitializers = true
}
allOpen {
    annotation("javax.persistence.Entity")
    annotation("javax.persistence.MappedSuperclass")
    annotation("javax.persistence.Embeddable")
}

group = "com.compig"
version = "0.0.1-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_11

repositories {
    mavenCentral()
    google()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-data-rest")
    implementation("org.springframework.boot:spring-boot-starter-security:2.6.4")
    implementation("org.springframework.boot:spring-boot-starter-validation:2.6.3")

    implementation("org.springframework.security.oauth.boot:spring-security-oauth2-autoconfigure:2.6.3")
    implementation("org.springframework.security:spring-security-oauth2-authorization-server:0.2.2")

    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.6.10")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-common:1.6.10")

    implementation("io.github.microutils:kotlin-logging:1.12.5") // Logging

    runtimeOnly("com.h2database:h2:2.0.206")
    implementation("mysql:mysql-connector-java:8.0.28")

    compileOnly("org.projectlombok:lombok:1.18.22")
    implementation("org.projectlombok:lombok-mapstruct-binding:0.2.0")

    implementation("org.apache.commons:commons-lang3:3.12.0")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    implementation("io.jsonwebtoken:jjwt-api:0.11.2")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.2")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.2")

    implementation("org.modelmapper:modelmapper:3.0.0")
    implementation("org.mapstruct:mapstruct:1.4.2.Final")
    kapt("org.mapstruct:mapstruct-processor:1.4.2.Final")
    kaptTest("org.mapstruct:mapstruct-processor:1.4.2.Final")

    implementation("com.google.code.gson:gson:2.9.0")
    implementation("com.googlecode.json-simple:json-simple:1.1.1")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test:5.6.2")

}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict")
        jvmTarget = "11"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
