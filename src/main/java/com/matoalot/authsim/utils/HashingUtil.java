package com.matoalot.authsim.utils;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.apache.commons.codec.digest.DigestUtils;
import org.mindrot.jbcrypt.BCrypt;


/**
 * Utility class for hashing and verifying passwords using SHA-256, BCrypt, and Argon2id.
 */
public class HashingUtil {
    // BCrypt parameters.
    private static final int COST_FACTOR = 12; // BCrypt cost factor.

    // Argon2id parameters.
    private static final int ITERATIONS = 1;
    private static final int MEMORY = 65536; // 64 MB
    private static final int PARALLELISM = 1;


    /**
     * Hashes a password using SHA-256 with a given salt.
     * @param password The password to hash.
     * @param salt The salt to use.
     * @return The SHA-256 hashed password.
     */
    public static String hashWithSHA256(String password, String salt) {
        return DigestUtils.sha256Hex(password + salt);
    }

    /**
     * Verifies a password against SHA-256 hash with a given salt.
     * @param password The password to verify.
     * @param salt The salt used in hashing.
     * @param expectedHash The expected SHA-256 hash.
     * @return True if the password matches the hash, false otherwise.
     */
    public static boolean verifySHA256(String password, String salt, String expectedHash) {
        String computedHash = hashWithSHA256(password, salt);
        return computedHash.equals(expectedHash);
    }

    /**
     * Hashes a password using BCrypt with a generated salt.
     * @param password The password to hash.
     * @return The BCrypt hashed password.
     */
    public static String hashWithBCrypt(String password) {
        // Generate a salt with default cost factor.
        String salt = BCrypt.gensalt(COST_FACTOR);

        // Hash the password with the generated salt.
        return BCrypt.hashpw(password, salt);
    }

    /**
     * Verifies a password against a BCrypt hash.
     * @param password The password to verify.
     * @param expectedHash The expected BCrypt hash.
     * @return True if the password matches the hash, false otherwise.
     */
    public static boolean verifyBCrypt(String password, String expectedHash) {
        return BCrypt.checkpw(password, expectedHash);
    }

    /**
     * Hashes a password using Argon2id with specified parameters.
     * @param password The password to hash.
     * @return The Argon2id hashed password.
     */
    public static String hashWithArgon2id(String password) {
        // Create an Argon2 instance for Argon2id.
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

        // Hash the password with specified parameters.
        return argon2.hash(ITERATIONS, MEMORY, PARALLELISM, password.toCharArray());
    }

    /**
     * Verifies a password against an Argon2id hash.
     * @param password The password to verify.
     * @param expectedHash The expected Argon2id hash.
     * @return True if the password matches the hash, false otherwise.
     */
    public static boolean verifyArgon2id(String password, String expectedHash) {
        // Create an Argon2 instance for Argon2id.
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

        // Verify the password against the expected hash.
        return argon2.verify(expectedHash, password.toCharArray());
    }


    /**
     * Generate a salt value using BCrypt package.
     * @return Random salt.
     */
    public static String generateSalt() {
        // Generate a random salt using BCrypt's gensalt method.
        return BCrypt.gensalt();
    }
}
