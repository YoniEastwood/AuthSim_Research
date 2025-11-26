package com.matoalot.authsim.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HashingUtilTest {


    @DisplayName("Test SHA-256 Hashing and Verification With Correct values")
    @ParameterizedTest(name = "Password: {0}, salt: {1}")
    @CsvSource({
            "password123,salt123",
            "helloWorld,randomSalt",
            "P@ssw0rd!,S@ltValue",
            "123456,abcdef",
            "complexPassword!@#,123!@#"
    })
    void testSHA256HashingAndVerificationWithCorrectValues(String password, String salt) {
        // Hash the password.
        String hashedPassword = HashingUtil.hashWithSHA256(password, salt);
        // Verify the hashed password. Should be true.
        assertTrue(HashingUtil.verifySHA256(password, salt, hashedPassword),
                "Password should verify against itself");
    }

    @DisplayName("Test SHA-256 Hashing against wrong values")
    @ParameterizedTest(name = "Password: {0}, salt: {1}, wrong password: {2}")
    @CsvSource({
            "password123,salt123, password",
            "helloWorld,randomSalt, ",
            "P@ssw0rd!,S@ltValue,nothing",
            "123456,abcdef,aeui",
            "complexPassword!@#,123!@#,134"
    })
    void testSha256HashingAgainstWrongPassword(String password, String salt, String wrongPassword) {
        String rightPasswordHash = HashingUtil.hashWithSHA256(password, salt);
        assertFalse(HashingUtil.verifySHA256(wrongPassword, salt, rightPasswordHash),
                "Wrong password Should have different hash value");
    }


    @DisplayName("Test BCrypt Hashing and Verification against correct password")
    @ParameterizedTest(name = "password: {0}")
    @ValueSource(strings = {"password", "auit", "util"})
    void testBCryptHashingAndVerifyAgainstCorrectValue(String password) {
        String hashValue = HashingUtil.hashWithBCrypt(password);

        assertTrue(HashingUtil.verifyBCrypt(password, hashValue),
                "Password should verify against itself.");
    }


    @DisplayName("Test Bcrypt Hashing against wrong values")
    @ParameterizedTest(name = "Password: {0}, wrong password: {1}")
    @CsvSource({
            "password123, password",
            "helloWorld, ",
            "P@ssw0rd!,nothing",
            "123456,wrongPassword",
            "complexPassword!@#,123!@#,134"
    })
    void testBcryptHashingAgainstWrongPassword(String password, String wrongPassword) {
        String rightPasswordHash = HashingUtil.hashWithBCrypt(password);
        assertFalse(HashingUtil.verifyBCrypt(wrongPassword, rightPasswordHash),
                "Wrong password Should have different hash value");
    }



    @DisplayName("Test Argon2id Hashing and Verification against correct password")
    @ParameterizedTest(name = "password: {0}")
    @ValueSource(strings = {"password", "auit", "util"})
    void testArgon2idHashingAndVerifyAgainstCorrectValue(String password) {
        String hashValue = HashingUtil.hashWithArgon2id(password);

        assertTrue(HashingUtil.verifyArgon2id(password, hashValue),
                "Password should verify against itself.");
    }


    @DisplayName("Test Argon2id Hashing against wrong values")
    @ParameterizedTest(name = "Password: {0}, wrong password: {1}")
    @CsvSource({
            "password123, password",
            "helloWorld, ",
            "P@ssw0rd!,nothing",
            "123456,wrongPassword",
            "complexPassword!@#,123!@#,134"
    })
    void testArgon2idHashingAgainstWrongPassword(String password, String wrongPassword) {
        String rightPasswordHash = HashingUtil.hashWithArgon2id(password);
        assertFalse(HashingUtil.verifyArgon2id(wrongPassword, rightPasswordHash),
                "Wrong password Should have different hash value");
    }


}