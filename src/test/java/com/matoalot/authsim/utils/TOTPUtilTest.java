package com.matoalot.authsim.utils;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TOTPUtilTest {

    @Test
    void testTOTPVerificationFlow() {
        String secrete = TOTPUtil.generateSecret(); // Get a secrete.

        assertNotNull(secrete, "Secrete should not be null.");
        assertFalse(secrete.isEmpty(), "Secrete should not be empty");

        String validCode = TOTPUtil.generateCurrentCode(secrete);

        for (int i = 0; i < 10; i++) {
            long startTime = System.currentTimeMillis();
            assertTrue(TOTPUtil.verify(secrete, validCode), "Should except a valid code");
            long endTime = System.currentTimeMillis();
            System.out.println("TOTP verification took " + (endTime - startTime) + " ms");
        }

        assertFalse(TOTPUtil.verify(secrete, "248523"),
                "Should not except a random code " +
                        "(note: there is a chance of 1 in 1,000,000 that this will fail if I generated the correct code)");




    }

}
