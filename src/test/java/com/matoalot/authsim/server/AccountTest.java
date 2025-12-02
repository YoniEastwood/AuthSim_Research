package com.matoalot.authsim.server;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalUnit;

import static org.junit.jupiter.api.Assertions.*;

public class AccountTest {
    Account a1, a2;


    @BeforeEach
    void setUp() {
        a1 = new Account.AccountBuilder("user1", "password123")
                .useSaltManually("manualSaltValue")
                .build();
        a2 = new Account.AccountBuilder("user2", "password456")
                .build();
    }


    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void testInvalidUsername(String badUsername) {
        assertThrows(IllegalArgumentException.class, () ->
                new Account.AccountBuilder(badUsername, "validPass").build()
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void testInvalidPassword(String badPassword) {
        assertThrows(IllegalArgumentException.class, () ->
                new Account.AccountBuilder("validUser", badPassword).build()
        );
    }


    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void testInvalidSalt(String badSalt) {
        assertThrows(IllegalArgumentException.class, () ->
                new Account.AccountBuilder("validUser", "validPass")
                        .useSaltManually(badSalt)
                        .build()
        );
    }

    @Test
    void testValidSalt() {
        Account a = new Account.AccountBuilder("valid", "valid")
                .useSaltManually("validSalt")
                .build();

        assertTrue(a.isUsingSaltManually(), "Account with salt should return true");
        assertEquals(a.getManualSalt(), "validSalt", "Returning wrong Salt value");
    }

    @Test
    void testIsUsingSaltValue() {
        assertTrue(a1.isUsingSaltManually(), "isUsingSalt should return true when using salt");
        assertFalse(a2.isUsingSaltManually(), "isUsingSalt should return false when not using salt.");
    }


    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void testEnableTOTPWithBadParameter(String secrete) {
        Throwable e = assertThrows(IllegalArgumentException.class, () ->{
            a1.enableTOTP(secrete);
        });

        System.out.println("Exception message: " + e.getMessage());
    }

    @Test
    void testTOTPFlow() {
        assertFalse(a1.isUsingTOTP(), "New account should not use TOTP");

        assertThrows(IllegalStateException.class, () -> {
            a1.getSecretTOTP();
        }, "Should not allow requesting TOTP when it is not enabled");

        // Enable TOTP
        a1.enableTOTP("validTOTP");

        assertTrue(a1.isUsingTOTP(), "After enabling TOTP, account should know that.");

        assertEquals(a1.getSecretTOTP(), "validTOTP", "Account should return the correct TOTP secrete");
    }



    @Test
    @DisplayName("Test lock account flow")
    void testLockFlow() {
        assertFalse(a1.isAccountLocked(), "New account shouldn't be locked");

        assertThrows(IllegalArgumentException.class, () -> {
            a1.lockAccountUntil(null);
        }, "Should not accept null time pointer");

        // Lock the account for 5 minutes
        Instant time = Instant.now().plus(Duration.ofMinutes(5));
        a1.lockAccountUntil(time);

        // Assert account is locked.
        assertTrue(a1.isAccountLocked(), "Account should be locked");

        // Assert that lock cannot be overwritten
        time = time.minus(Duration.ofMinutes(10));
        a1.lockAccountUntil(time);
        assertTrue(a1.isAccountLocked(), "Account should not allow overwriting timeUntilUnlock with a shorter time");

    }

    @Test
    void testReturnHashPassword() {
        Account a = new Account.AccountBuilder("ValidUsername", "ValidPassword")
                .build();

        assertEquals(a.getPasswordHash(), "ValidPassword");
    }










}
