package com.matoalot.authsim.server;

import com.google.gson.annotations.SerializedName;
import com.matoalot.authsim.ExperimentManager;
import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.model.LoginState;
import com.matoalot.authsim.model.RegisterState;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ServerTest {
    private static Server sha256;
    private static Server sha2456WithPepperAndCaptcha2;
    private static Server bcrypt;
    private static Server Argon2id;


    @BeforeEach
    public void setup() {
        sha256 = new Server(HashAlgorithm.SHA256, false, 0);
        sha2456WithPepperAndCaptcha2 = new  Server(HashAlgorithm.SHA256, true, 2);

        bcrypt = new  Server(HashAlgorithm.BCRYPT, false, 0);
        Argon2id = new Server(HashAlgorithm.ARGON2ID, false, 0);
    }


    @ParameterizedTest
    @NullAndEmptySource
    void testEmptyUsername(String username) {
        assertEquals(RegisterState.FAILURE_INVALID_LENGTH, sha256.register(username, "password123", false),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during registration");

        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.login(username, "password123"),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during login");

        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.loginWithCAPTCHA(username, "password123", sha256.generateCPATCHA(username)),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during login with CAPTCHA");

        assertEquals(LoginState.FAILURE_TOTP_INVALID, sha256.verifyTOTP(username, "123456"),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during TOTP verification");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void testEmptyPassword(String password) {
        assertEquals(RegisterState.FAILURE_INVALID_LENGTH, sha256.register("username", password, false),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during registration");

        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.login("username", password),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during login");

        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.loginWithCAPTCHA("username", password, sha256.generateCPATCHA("username")),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during login with CAPTCHA");

        assertEquals(LoginState.FAILURE_TOTP_INVALID, sha256.verifyTOTP("username", password),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during TOTP verification");
    }


    @DisplayName("Test Registration and Login with valid credentials")
    @ParameterizedTest(name = "username: {0}, password: {1}")
    @CsvSource ({
            "user1, password123",
            "user2, mySecurePass!",
            "testUser, Pa$$w0rd",
            "alice, qwertyuiop"
    })
    void testRegistrationAndLogin(String username, String password) {
        // Test registration
        assertEquals(RegisterState.SUCCESS, sha256.register(username, password, false),
                "Expected SUCCESS for valid registration");

        // Test login
        assertEquals(LoginState.SUCCESS, sha256.login(username, password),
                "Expected SUCCESS for valid login");
        
    }


    @DisplayName("Test Registration and Login with invalid credentials")
    @ParameterizedTest(name = "username: {0}, password: {1}, invalidPassword: {2}")
    @CsvSource ({
            "user1, password, wrongPass",
            "user2, aeder, wrongPassword!",
            "user23, password123, sordu"
    })
    void testRegistrationAndLoginWithInvalidPassword(String username, String password, String invalidPassword) {
        // Test registration
        assertEquals(RegisterState.SUCCESS, sha256.register(username, password, false),
                "Expected SUCCESS for valid registration");

        // Test login with invalid password
        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.login(username, invalidPassword),
                "Expected FAILURE_BAD_CREDENTIALS for invalid login password");
    }





}