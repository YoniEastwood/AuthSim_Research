package com.matoalot.authsim.server;

import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.utils.HashingUtil;
import com.matoalot.authsim.utils.TOTPUtil;


class AuthService {


    /**
     * Creates a new account with the specified parameters.
     * @param username The username for the account.
     * @param password Password for the account.
     * @param enableTOTP Flag indicating if TOTP is enabled.
     * @param hashAlgorithm The hashing algorithm to use.
     * @return The created Account object.
     */
    static Account createAccount(
        String username, String password, boolean enableTOTP, HashAlgorithm hashAlgorithm) {
        // TODO: test arguments again for code robustness. Better to Create a helper Class for testing.

        String hashedPassword; // Hashed password to be computed.
        String salt = null; // If using manual salt.


        switch (hashAlgorithm) {
            case SHA256: // SHA-256 hashing with salt.
                 salt = HashingUtil.generateSalt();
                 hashedPassword = HashingUtil.hashWithSHA256(password, salt);
                 break;

            case BCRYPT: // BCrypt hashing. Handles salt internally.
                hashedPassword = HashingUtil.hashWithBCrypt(password);
                break;

            case ARGON2ID: // Argon2id hashing. Handles salt internally.
                hashedPassword = HashingUtil.hashWithArgon2id(password);
                break;
            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }

        // Build the account.
        Account.AccountBuilder accountBuilder = new Account.AccountBuilder(username, hashedPassword);

        // If using SHA-256, set the salt manually.
        if (hashAlgorithm == HashAlgorithm.SHA256) {
            accountBuilder = accountBuilder.useSaltManually(salt);
        }

        // If TOTP is enabled, generate and set the TOTP secret.
        if (enableTOTP) {
            accountBuilder.enableTOTP(TOTPUtil.generateSecret());
        }

        return accountBuilder.build(); // Return the created account.
    }


    /**
     * Authenticates a user by verifying the password attempt against the stored hash.
     * @param account The account to authenticatePassword.
     * @param passwordAttempt The password attempt to verify.
     * @param hashAlgorithm The hashing algorithm used for the account.
     * @return True if authentication is successful, false otherwise.
     */
    static boolean authenticatePassword(Account account, String passwordAttempt, HashAlgorithm hashAlgorithm) {
        // Validate arguments
        if (account == null) {
            throw new IllegalArgumentException("Account is null");
        }
        if (passwordAttempt == null) {
            throw new IllegalArgumentException("Password is null");
        }

        // This is an internal method. This shouldn't be called if account is locked.
        if (account.isAccountLocked()) {
            throw new IllegalStateException("Trying to authenticate while account is locked.");
        }


        boolean correctPassword = false;
        switch (hashAlgorithm) {
            case SHA256:
                // Should never happen. SHA-256 always uses salt.
                if(!account.isUsingSaltManually()) {
                    throw new IllegalStateException("Account should always use manual salt for SHA-256.");
                }
                String salt = account.getManualSalt();
                correctPassword = HashingUtil.verifySHA256(passwordAttempt, salt,  account.getPasswordHash());
                break;

            case BCRYPT:
                correctPassword = HashingUtil.verifyBCrypt(passwordAttempt, account.getPasswordHash());
                break;

            case ARGON2ID:
                correctPassword = HashingUtil.verifyArgon2id(passwordAttempt, account.getPasswordHash());
                break;

            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }

        // Handle the login attempt counter.
        if (correctPassword) {
            account.resetAttemptLoginCounter();
        }
        else {
            account.badLoginAttemptsIncreaser();
        }

        return correctPassword;
    }




}
