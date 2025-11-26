package com.matoalot.authsim.server;

import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.utils.HashingUtil;
import com.matoalot.authsim.utils.TOTPUtil;


class AuthService {


    /**
     * Creates a new account with the specified parameters.
     * @param username The username for the account.
     * @param password Passord for the account.
     * @param enableTOTP Flag indicating if TOTP is enabled.
     * @param hashAlgorithm The hashing algorithm to use.
     * @return The created Account object.
     */
    static Account createAccount(
        String username, String password, boolean enableTOTP, HashAlgorithm hashAlgorithm) {

        String hashedPassword; // Hashed password to be computed.
        String salt = null; // Salt value if used.


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
        Account.AccountBuilder account = new Account.AccountBuilder(username, hashedPassword);

        // If using SHA-256, set the salt manually.
        if (hashAlgorithm == HashAlgorithm.SHA256) {
            account = account.useSaltManually(salt);
        }

        // If TOTP is enabled, generate and set the TOTP secret.
        if (enableTOTP) {
            account.enableTOTP(TOTPUtil.generateSecret());
        }

        return account.build(); // Return the created account.
    }


    /**
     * Authenticates a user by verifying the password attempt against the stored hash.
     * @param account The account to authenticatePassword.
     * @param passwordAttempt The password attempt to verify.
     * @param hashAlgorithm The hashing algorithm used for the account.
     * @return True if authentication is successful, false otherwise.
     */
    static boolean authenticatePassword(Account account, String passwordAttempt, HashAlgorithm hashAlgorithm) {

        switch (hashAlgorithm) {
            case SHA256:
                if(!account.isUsingSaltManually()) {
                    throw new IllegalStateException("Account should always use manual salt for SHA-256.");
                }
                String salt = account.getManualSalt();
                return HashingUtil.verifySHA256(passwordAttempt, salt,  account.getPasswordHash());

            case BCRYPT:
                return HashingUtil.verifyBCrypt(passwordAttempt, account.getPasswordHash());

            case ARGON2ID:
                return HashingUtil.verifyArgon2id(passwordAttempt, account.getPasswordHash());

            default:
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }
    }

    static boolean authenticateTOTP(Account account, String totpAttempt) {
        if (!account.isUsingTOTP()) { // TODO: check already by account.getSecretTOTP()
            throw new IllegalStateException("Account is not using TOTP.");
        }

        return TOTPUtil.verify(account.getSecretTOTP(), totpAttempt);
    }












}
