package com.matoalot.authsim.server;

import com.google.gson.annotations.SerializedName;
import com.matoalot.authsim.ExperimentManager;
import com.matoalot.authsim.model.CaptchaState;
import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.model.LoginState;
import com.matoalot.authsim.model.RegisterState;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.ValueSources;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ServerTest {
    private static Server sha256;
    private static Server sha256WithPepperAndCaptcha2;
    private static Server bcrypt;
    private static Server Argon2id;


    @BeforeEach
    public void setup() {
        sha256 = new Server(HashAlgorithm.SHA256, false, 0);
        sha256WithPepperAndCaptcha2 = new  Server(HashAlgorithm.SHA256, true, 2);

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


    @DisplayName("Test Login with CAPTCHA")
    @ParameterizedTest(name = "loginAttemptsUntilCaptcha: {0}")
    @ValueSource(ints = { 2, 3, 5})
    void testLoginWithCAPTCHA(int loginAttemptsUntilCaptcha) {
        Server server = new Server(HashAlgorithm.SHA256, true, loginAttemptsUntilCaptcha);

        // Register user with CAPTCHA enabled
        String username = "captchaUser";
        String password = "captchaPass";
        String wrongPassword = "wrongPass";

         // Test registration
        assertEquals(RegisterState.SUCCESS, server.register(username, password, false),
                "Expected SUCCESS for valid registration with CAPTCHA");

        // Generate CAPTCHA
        String captcha = server.generateCPATCHA(username);

        // Attempt login until CAPTCHA is required.
        for (int i = 1; i < loginAttemptsUntilCaptcha; i++) {
            assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, server.login(username, wrongPassword),
                    "Expected Bad Credentials for wrong password");
        }

        // Expect CAPTCHA after reaching the threshold
        assertEquals(LoginState.FAILURE_REQUIRE_CAPTCHA, server.login(username, wrongPassword),
                "Expected FAILURE_CAPTCHA_REQUIRED after reaching login attempt threshold");
        assertEquals(LoginState.FAILURE_REQUIRE_CAPTCHA, server.login(username, password),
                "Expected FAILURE_REQUIRE_CAPTCHA for correct password");

        // Bad CAPTCHA correct password should fail
        assertEquals(CaptchaState.FAILURE_INCORRECT_CAPTCHA, server.verifyCAPTCHA(username, "wrongCaptcha"),
                "Expected FAILURE_CAPTCHA_INVALID for wrong CAPTCHA with correct password");
        // Still should require CAPTCHA
        assertEquals(LoginState.FAILURE_REQUIRE_CAPTCHA, server.login(username, wrongPassword),
                "Expected FAILURE_CAPTCHA_REQUIRED after incorrect CAPTCHA");

        // verify correct CAPTCHA
        assertEquals(CaptchaState.SUCCESS, server.verifyCAPTCHA(username, captcha),
                "Expected SUCCESS for correct CAPTCHA");
        // Now login should succeed with correct password
        assertEquals(LoginState.SUCCESS, server.login(username, password),
                "Expected SUCCESS for correct password after CAPTCHA verification");
    }


    // Test TOTP flow
    // Test lock account flow



}