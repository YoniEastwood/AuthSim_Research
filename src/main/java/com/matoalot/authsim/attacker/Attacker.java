package com.matoalot.authsim.attacker;

import com.matoalot.authsim.server.Server;
import com.matoalot.authsim.model.LoginState;
import com.matoalot.authsim.utils.PasswordGenerator;
import com.matoalot.authsim.model.HashAlgorithm;

import java.util.List;
import java.util.Random;

public class Attacker {
        private final Server server;
        private final List<String> usernames;
        private final int maxAttempts;
        private final long maxRunTimeMillis;

        public Attacker(Server server, List<String> usernames, int maxAttempts, long maxRunTimeMillis) {
            this.server = server;
            this.usernames = usernames;
            this.maxAttempts = maxAttempts;
            this.maxRunTimeMillis = maxRunTimeMillis;
        }
        public void bruteForceAllUsers() {
        long start = System.currentTimeMillis();

        for (String username : usernames) {

            int attempts = 0;

            System.out.println("=== Brute Force on " + username + " ===");

            for (String guess : PasswordGenerator.COMMON_PASSWORDS_LIST) {

                // אם עבר הזמן שהוגדר — מפסיקים
                if (System.currentTimeMillis() - start > maxRunTimeMillis) {
                    System.out.println("⏳ Time limit reached! stopping...");
                    return;
                }

                // אם עברנו את מספר הניסיונות — מפסיקים
                if (attempts >= maxAttempts) {
                    System.out.println("⚠ Max attempts reached for " + username);
                    break;
                }

                attempts++;

                LoginState state = server.login(username, guess);
                System.out.println("Trying: " + guess + " → " + state);

                if (state == LoginState.SUCCESS) {
                    System.out.println("FOUND PASSWORD: " + guess);
                    break;
                }

                if (state == LoginState.FAILURE_ACCOUNT_LOCKED) {
                    System.out.println("ACCOUNT LOCKED!");
                    break;
                }
            }
        }
    }
    public void passwordSpraying() {

        long start = System.currentTimeMillis();

        System.out.println("=== Password Spraying ===");

        for (String guess : PasswordGenerator.COMMON_PASSWORDS_LIST) {

            if (System.currentTimeMillis() - start > maxRunTimeMillis) {
                System.out.println("⏳ Time limit reached! stopping spraying...");
                return;
            }

            System.out.println("\nTrying password: " + guess);

            for (String username : usernames) {

                LoginState state = server.login(username, guess);

                if (state == LoginState.SUCCESS) {
                    System.out.println("SUCCESS!! " + username + " uses password: " + guess);
                }
            }
        }
    }

}

