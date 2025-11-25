package com.matoalot.authsim.server;


import java.time.Instant;

/**
 * Account class representing a user account.
 */
public class Account {
    private final String username; // Unique username of the account.
    private final String passwordHash; // Hashed password of the account.
    private int failedLoginAttempts; // Counter for failed login attempts since last success.

    private final String manualSalt; // Salt value. ONLY IF HASHING ALGORITHM DOESN'T HANDLE SALT INTERNALLY.
    private boolean isUsingSaltManually; // Flag indicating if salt is used.

    private boolean isUsingTOTP; // Flag indicating if TOTP is enabled.
    private String secretTOTP; // TOTP secret key if TOTP is enabled.

    // Timestamp until which the account is locked. Use secure time representation.
    private Instant accountLockedUntil;

    // Private constructor to enforce the use of the builder.
    private Account (AccountBuilder builder) {
        this.username = builder.username;
        this.passwordHash = builder.passwordHash;

        if (builder.isUsingSaltManually) {
            this.manualSalt = builder.manualSalt;
            this.isUsingSaltManually = true;
        } else {
            this.manualSalt = null;
            this.isUsingSaltManually = false;
        }
    }

    /**
     * Enables TOTP for the account with the provided secret.
     * @param secretTOTP The TOTP secret key.
     */
    void enableTOTP(String secretTOTP) {
        if (secretTOTP == null || secretTOTP.isEmpty()) {
            throw new IllegalArgumentException("TOTP secret cannot be null or empty");
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
        if (this.accountLockedUntil != null && accountLockedUntil.isAfter(unlockTime)) {
            return; // Existing lock is longer, do nothing.
        }

        // Set the new lock expiration time.
        this.accountLockedUntil = unlockTime;
    }

    /**
     * Builder class for Account. Has package-private access.
     */
    static class AccountBuilder {
        private String username; // Username of the account. Should be unique and enforced by the server.
        private String passwordHash; // Hashed password of the account.
        private String manualSalt; // Salt value if used.
        private boolean isUsingSaltManually = false; // Flag indicating if salt is used.
        private boolean isUsingTOTP = false; // Flag indicating if TOTP is enabled.
        private String secretTOTP; // TOTP secret key if TOTP is enabled.

        AccountBuilder(String username, String passwordHash) {
            this.username = username;
            this.passwordHash = passwordHash;

            // Basic validation
            if (username == null || username.isEmpty()) {
                throw new IllegalArgumentException("Username cannot be null or empty");
            }
            if (passwordHash == null || passwordHash.isEmpty()) {
                throw new IllegalArgumentException("Password hash cannot be null or empty");
            }
        }

        AccountBuilder useSaltManually(String salt) {
            // Basic validation.
            if(salt == null || salt.isEmpty()) {
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
