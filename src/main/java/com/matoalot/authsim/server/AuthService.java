package com.matoalot.authsim.server;

import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.utils.HashingUtil;


class AuthService {


    /**
     * Creates a new account with the specified parameters.
     * @param username The username for the account.
     * @param password Password for the account.
     * @param hashAlgorithm The hashing algorithm to use.
     * @return The created Account object.
     */
    static Account createAccount(
        String username, String password, HashAlgorithm hashAlgorithm) {

        // Validate arguments
        if (username == null || username.isBlank() ||
            password == null || password.isBlank()) {
            throw new IllegalArgumentException("Username or password is null/empty");
        }

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

        return correctPassword;
    }




}
