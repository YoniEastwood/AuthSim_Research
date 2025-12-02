package com.matoalot.authsim.server;


import java.time.Instant;

/**
 * Account class representing a user account.
 */
class Account {
    private final String username; // Unique username of the account.
    private final String passwordHash; // Hashed password of the account.
    private int failedLoginAttempts = 0; // Counter for failed login attempts since last success.

    private final String manualSalt; // Salt value. ONLY IF HASHING ALGORITHM DOESN'T HANDLE SALT INTERNALLY.
    private final boolean isUsingSaltManually; // Flag indicating if salt is used.

    private boolean isUsingTOTP; // Flag indicating if TOTP is enabled.
    private String secretTOTP; // TOTP secret key if TOTP is enabled.

    // Timestamp until which the account is locked. Use secure time representation.
    private Instant accountLockedUntil;

    // Private constructor to enforce the use of the builder.
    private Account (AccountBuilder builder) {
        // check for null argument.
        if(builder == null) {
            throw new IllegalArgumentException("Error: builder is null. Should never happen.");
        }

        this.username = builder.username;
        this.passwordHash = builder.passwordHash;

        // Set Salt manually if needed.
        if (builder.isUsingSaltManually) {
            this.manualSalt = builder.manualSalt;
            this.isUsingSaltManually = true;
        } else {
            this.manualSalt = null;
            this.isUsingSaltManually = false;
        }
    }

    /**
     * Resets the login attempts
     */
    void resetAttemptLoginCounter() {
        // Check if account is locked.
        if (isAccountLocked()) {
            throw new IllegalArgumentException("Trying to reset and login attempts while account locked is forbitten");
        }
        // Reset the login attempts.
        failedLoginAttempts = 0;
    }

    /**
     * Increase the failed login counter by one.
     */
    void badLoginAttemptsIncreaser() {
        failedLoginAttempts += 1;
    }

    /**
     * Get the failed login attempts counter.
     * @return failed logins since last success login.
     */
    int getBadLoginAttemptsCounter() {return failedLoginAttempts;}

    /**
     * Enables TOTP for the account with the provided secret.
     * @param secretTOTP The TOTP secret key.
     */
    void enableTOTP(String secretTOTP) {
        if (secretTOTP == null || secretTOTP.isBlank()) {
            throw new IllegalArgumentException("TOTP secret cannot be null or empty");
        }

        if(isUsingTOTP) {
            throw new IllegalStateException("TOTP already enabled");
        }

        this.isUsingTOTP = true;
        this.secretTOTP = secretTOTP;
    }


    /**
     * Returns whether the account is using manual salt.
     * @return True if using manual salt, false otherwise.
     */
    boolean isUsingSaltManually() {return isUsingSaltManually;}

    /**
     * Returns the manual salt value.
     * @return The manual salt value.
     */
    String getManualSalt() {
        if (!isUsingSaltManually) {
            throw new IllegalStateException("Account is not using manual salt.");
        }
        return manualSalt;
    }

    /**
     * Returns whether TOTP is enabled for the account.
     * @return True if TOTP is enabled, false otherwise.
     */
    boolean isUsingTOTP() {return isUsingTOTP;}

    /**
     * Returns the TOTP secret key.
     * @return The TOTP secret key.
     */
    String getSecretTOTP() {
        if(!isUsingTOTP()) {
            throw new IllegalStateException("Account is not using TOTP." );
        }
        return secretTOTP;
    }


    /**
     * Returns the password hash.
     * @return The password hash.
     */
    String getPasswordHash() {return passwordHash;}


    /**
     * Checks if the account is currently locked.
     * @return True if the account is locked, false otherwise.
     */
    boolean isAccountLocked() {
        if (accountLockedUntil == null) {
            return false;
        }

        // Compare current time with the lock expiration time.
        Instant now = Instant.now();
        return now.isBefore(accountLockedUntil);
    }

    /**
     * Locks the account until the specified unlock time.
     * @param unlockTime The time until which the account should be locked.
     */
    void lockAccountUntil(Instant unlockTime) {
        if (unlockTime == null) {
            throw new IllegalArgumentException("Unlock time is null. Should never happen.");
        }

        // Can only extend lock time, not shorten.
        if (this.accountLockedUntil != null && accountLockedUntil.isAfter(unlockTime)) {
            return;
        }

        // Set the new lock expiration time.
        this.accountLockedUntil = unlockTime;
    }

    /**
     * Builder class for Account. Has package-private access.
     */
    static class AccountBuilder {
        private final String username; // Username of the account. Should be unique and enforced by the server.
        private final String passwordHash; // Hashed password of the account.
        private String manualSalt; // Salt value if used.
        private boolean isUsingSaltManually = false; // Flag indicating if salt is used.
        private boolean isUsingTOTP = false; // Flag indicating if TOTP is enabled.
        private String secretTOTP; // TOTP secret key if TOTP is enabled.

        /**
         * Creates a builder with a username and hashed password.
         * @param username Username.
         * @param passwordHash Hashed password.
         */
        AccountBuilder(String username, String passwordHash) {
            // Check Argument
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username cannot be null or empty");
            }
            if (passwordHash == null || passwordHash.isBlank()) {
                throw new IllegalArgumentException("Password hash cannot be null or empty");
            }

            this.username = username;
            this.passwordHash = passwordHash;
        }


        AccountBuilder useSaltManually(String salt) {
            // Basic validation.
            if(salt == null || salt.isBlank()) {
                throw new IllegalArgumentException("Salt cannot be null or empty");
            }

            this.manualSalt = salt;
            this.isUsingSaltManually = true;
            return this;
        }

        AccountBuilder enableTOTP(String secretTOTP) {
            // Basic validation.
            if (secretTOTP == null || secretTOTP.isEmpty()) {
                throw new IllegalArgumentException("TOTP secret cannot be null or empty");
            }

            this.isUsingTOTP = true;
            this.secretTOTP = secretTOTP;
            return this;
        }

        Account build() {
            return new Account(this);
        }
    }
}
