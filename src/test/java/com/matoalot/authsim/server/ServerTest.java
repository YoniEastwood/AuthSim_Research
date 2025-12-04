package com.matoalot.authsim.server;


import com.matoalot.authsim.Logger.CsvLogger;
import com.matoalot.authsim.model.CaptchaState;
import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.model.LoginState;
import com.matoalot.authsim.model.RegisterState;
import com.matoalot.authsim.utils.TOTPUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ServerTest {
    private static Server sha256;

    @BeforeEach
    void setup() {
        sha256 = new Server(
                HashAlgorithm.SHA256,
                false,
                0,
                0,
                5,
                50,
                new CsvLogger("test_log.csv")
        );
    }



    @ParameterizedTest
    @NullAndEmptySource
    void testEmptyUsername(String username) {
        assertEquals(RegisterState.FAILURE_INVALID_LENGTH, sha256.register(username, "password123"),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during registration");

        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.login(username, "password123"),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during login");

        assertEquals(LoginState.FAILURE_TOTP_INVALID, sha256.verifyTOTP(username, "123456"),
                "Expected FAILURE_BAD_CREDENTIALS for invalid username during TOTP verification");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void testEmptyPassword(String password) {
        assertEquals(RegisterState.FAILURE_INVALID_LENGTH, sha256.register("username", password),
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
        assertEquals(RegisterState.SUCCESS, sha256.register(username, password),
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
        assertEquals(RegisterState.SUCCESS, sha256.register(username, password),
                "Expected SUCCESS for valid registration");

        // Test login with invalid password
        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.login(username, invalidPassword),
                "Expected FAILURE_BAD_CREDENTIALS for invalid login password");
    }


    @DisplayName("Test Login with CAPTCHA")
    @ParameterizedTest(name = "loginAttemptsUntilCaptcha: {0}")
    @ValueSource(ints = { 2, 3, 5})
    void testLoginWithCAPTCHA(int loginAttemptsUntilCaptcha) {
        Server server = new Server(HashAlgorithm.SHA256,
                true,
                loginAttemptsUntilCaptcha,
                0,
                5,
                50,
                new CsvLogger("test_log.csv")
        );

        // Register user with CAPTCHA enabled
        String username = "captchaUser";
        String password = "captchaPass";
        String wrongPassword = "wrongPass";

         // Test registration
        assertEquals(RegisterState.SUCCESS, server.register(username, password),
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

    @DisplayName("Test Registration and Login with different hash algorithms")
    @ParameterizedTest(name = "hashAlgorithm: {0}, username: {1}, password: {2}, wrongPassword: {3}")
    @CsvSource({
            "SHA256, userSHA256, passSHA256, wrongSHA256",
            "BCRYPT, userBcrypt, passBcrypt, wrongBcrypt",
            "ARGON2ID, userArgon2id, passArgon2id, wrongArgon2id"
    })
    void testRegistrationAndLoginWithDifferentHashAlgorithms(HashAlgorithm hashAlgorithm, String username, String password, String wrongPassword) {
        Server server = new Server(
                hashAlgorithm,
                false,
                0,
                0,
                5,
                50,
                new CsvLogger("test_log.csv")
        );

        // Test registration
        assertEquals(RegisterState.SUCCESS, server.register(username, password),
                "Expected SUCCESS for valid registration with " + hashAlgorithm);

        // Test login with correct password
        assertEquals(LoginState.SUCCESS, server.login(username, password),
                "Expected SUCCESS for valid login with " + hashAlgorithm);

        // Test login with wrong password
        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, server.login(username, wrongPassword),
                "Expected FAILURE_BAD_CREDENTIALS for invalid login with " + hashAlgorithm);
    }

    @DisplayName("Test registration and login with pepper")
    @ParameterizedTest(name = "hashAlgorithm: {0}, username: {1}, password: {2}, wrongPassword: {3}")
    @CsvSource({
            "SHA256, userPepperSHA256, passPepperSHA256, wrongPepperSHA256",
            "BCRYPT, userPepperBcrypt, passPepperBcrypt, wrongPepperBcrypt",
            "ARGON2ID, userPepperArgon2id, passPepperArgon2id, wrongPepperArgon2id"
    })
    void testRegistrationAndLoginWithPepper(HashAlgorithm hashAlgorithm, String username, String password, String wrongPassword) {
        Server server = new Server(
                hashAlgorithm,
                true,
                0,
                0,
                5,
                50,
                new CsvLogger("test_log.csv")
        );

        // Test registration
        assertEquals(RegisterState.SUCCESS, server.register(username, password),
                "Expected SUCCESS for valid registration with pepper using " + hashAlgorithm);
        // Test login with correct password
        assertEquals(LoginState.SUCCESS, server.login(username, password),
                "Expected SUCCESS for valid login with pepper using " + hashAlgorithm);
        // Test login with wrong password
        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, server.login(username, wrongPassword),
                "Expected FAILURE_BAD_CREDENTIALS for invalid login with pepper using " + hashAlgorithm);
    }


    @Test
    void testTotpSetup() {
        String username = "totpSetupUser";
        String password = "totpSetupPass";

        assertEquals(RegisterState.SUCCESS, sha256.register(username, password),
                "Expected SUCCESS for valid registration");

        // Enable TOTP and get secret
        String totpSecret = sha256.enableTOTPForUser(username, password);
        assertEquals(true, totpSecret != null && !totpSecret.isBlank(),
                "Expected non-empty TOTP secret after enabling TOTP");

        // Login should fail with wrong password
        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, sha256.login(username, "wrongPass"),
                "Expected FAILURE_BAD_CREDENTIALS for wrong password");

        // Login should request TOTP
        assertEquals(LoginState.FAILURE_TOTP_REQUIRED, sha256.login(username, password),
                "Expected TOTP Request for valid login");

        // Login should fail with wrong TOTP
        assertEquals(LoginState.FAILURE_TOTP_INVALID, sha256.verifyTOTP(username, "wrongTOTP"),
                "Expected FAILURE_TOTP_INVALID for wrong TOTP");

        // Login should succeed with correct TOTP
        String currentTOTP = TOTPUtil.generateCurrentCode(totpSecret);
        assertEquals(LoginState.SUCCESS, sha256.verifyTOTP(username, currentTOTP),
                "Expected SUCCESS for correct TOTP");
    }


    @DisplayName("Test to many bad TOTP logins should Lock account")
    void testTOTPFlow() {
        Server server = new Server(
                HashAlgorithm.SHA256,
                false,
                0,
                0,
                5,
                50,
                new CsvLogger("test_log.csv")
        );

        String username = "totpUser";
        String password = "totpPass";

        // Register user
        assertEquals(RegisterState.SUCCESS, server.register(username, password),
                "Expected SUCCESS for valid registration");

        // Enable TOTP and get secret
        String totpSecret = server.enableTOTPForUser(username, password);
        assertEquals(true, totpSecret != null && !totpSecret.isBlank(),
                "Expected non-empty TOTP secret after enabling TOTP");

        // Login should succeed but ask for TOTP
        assertEquals(LoginState.FAILURE_TOTP_REQUIRED, server.login(username, password),
                "Expected TOTP Request for valid login");

        // Simulate TOTP verification attempts
        for (int i = 1; i <= 5; i++) {
            assertEquals(LoginState.FAILURE_TOTP_INVALID, server.verifyTOTP(username, "wrongTOTP"),
                    "Expected FAILURE_TOTP_INVALID for wrong TOTP attempt " + i);
        }

        // Next attempt should result in session lock
        assertEquals(LoginState.FAILURE_ACCOUNT_LOCKED, server.verifyTOTP(username, "wrongTOTP"),
                "Expected FAILURE_ACCOUNT_LOCKED after exceeding TOTP attempts");

    }


    @DisplayName("Test account lock after too many bad logins")
    @ParameterizedTest(name = "badLoginAttemptsUntilSessionLock: {0}")
    @ValueSource(ints = {1, 2, 3, 5})
    void testAccountLockAfterBadLogins(int badLoginAttemptsUntilSessionLock) {
        Server server = new Server(
                HashAlgorithm.SHA256,
                false,
                0,
                badLoginAttemptsUntilSessionLock,
                1,
                50,
                new CsvLogger("test_log.csv")
        );

        String username = "lockUser";
        String password = "lockPass";

        // Register user
        assertEquals(RegisterState.SUCCESS, server.register(username, password),
                "Expected SUCCESS for valid registration");

        // Simulate bad login attempts
        for (int i = 1; i <= badLoginAttemptsUntilSessionLock; i++) {
            assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, server.login(username, "wrongPass"),
                    "Expected FAILURE_BAD_CREDENTIALS for wrong password attempt " + i);
        }

        // Next attempt should result in account lock
        assertEquals(LoginState.FAILURE_ACCOUNT_LOCKED, server.login(username, "wrongPass"),
                "Expected FAILURE_ACCOUNT_LOCKED after exceeding bad login attempts");
    }

    // Test unlock after lock time expires.
    @Test
    void testLockAndUnlock() {
        Server server = new Server(
                HashAlgorithm.SHA256,
                false,
                0,
                2, // 2 bad attempts to lock
                1, // 1 minute lock time
                50,
                new CsvLogger("test_log.csv")
        );

        String username = "tempLockUser";
        String password = "tempLockPass";

        assertEquals(RegisterState.SUCCESS, server.register(username, password),
                "Expected SUCCESS for valid registration");

        // Simulate bad login attempts to trigger lock
        for (int i = 1; i <= 2; i++) {
            assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, server.login(username, "wrongPass"),
                    "Expected FAILURE_BAD_CREDENTIALS for wrong password attempt " + i);
        }

        // Account should be locked now
        assertEquals(LoginState.FAILURE_ACCOUNT_LOCKED, server.login(username, "wrongPass"),
                "Expected FAILURE_ACCOUNT_LOCKED after exceeding bad login attempts");

        try {
            TimeUnit.MINUTES.sleep(1);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Sleep interrupted: " + e.getMessage());
        }

        assertEquals(LoginState.FAILURE_BAD_CREDENTIALS, server.login(username, "wrongPass"),
                "Expected FAILURE_BAD_CREDENTIALS after lock time expired with wrong password");
        assertEquals(LoginState.SUCCESS, server.login(username, password),
                "Expected SUCCESS after lock time expired with correct password");

    }
}