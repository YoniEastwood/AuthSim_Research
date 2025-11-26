package com.matoalot.authsim.utils;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

public class TOTPUtil {

    /**
     * Generates a random secret key for TOTP.
     * Uses dev.samstevens.totp package.
     * @return A randomly generated secret key as a String.
     */
    public static String generateSecret() {
        SecretGenerator secretGenerator = new DefaultSecretGenerator(); // Default is 32 characters.
        return secretGenerator.generate();
    }

    /**
     * Verifies a TOTP code against a secret.
     * Uses dev.samstevens.totp package.
     * @param secret The shared secret key.
     * @param codeFromUser The TOTP code provided by the user.
     * @return true if the code is valid, false otherwise.
     */
    public static boolean verify(String secret, String codeFromUser) {

        // Set up the verifier and time.
        TimeProvider timeProvider = new SystemTimeProvider();
        DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator();
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        verifier.setAllowedTimePeriodDiscrepancy(1); // Allow 1 time step discrepancy (30 seconds each).
        verifier.setTimePeriod(30); // Generate new code every 30 sec.

        // Verify the code adn return the result.
        return verifier.isValidCode(secret, codeFromUser);
    }

    /**
     * Generates the current TOTP code based on the secret.
     * Returns a 6th digit code based on secrete code and time.
     * @param secret The shared secret key.
     * @return The current code.
     */
    public static String generateCurrentCode(String secret) {
        try {
            TimeProvider timeProvider = new SystemTimeProvider();
            DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator();

            // Calculate the current time bucket.
            long currentBucket = timeProvider.getTime() / 30;

            return codeGenerator.generate(secret, currentBucket);
        } catch (CodeGenerationException e) {
            e.printStackTrace();
            return null;
        }
    }


}
