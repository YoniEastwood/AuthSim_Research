package com.matoalot.authsim.utils;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
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
        String secret = secretGenerator.generate();
        return secret;
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

        // Verify the code adn return the result.
        return verifier.isValidCode(secret, codeFromUser);
    }




}
