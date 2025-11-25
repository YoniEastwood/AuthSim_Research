package com.matoalot.authsim.server;
import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.model.LoginState;

import java.util.HashMap;

/**
 * Server class that manages user accounts and authentication settings.
 */
public class Server {
    private final HashMap<String, Account> accounts; // List of user accounts.
    private final HashMap<String, Account> pendingTOTPAccounts; // Accounts pending TOTP verification.
    private final HashAlgorithm hashAlgorithm; // Password hashing algorithm.

    private final boolean isPepperEnabled; // Flag indicating if pepper is used.
    private final String pepper = "akd3#$adf(oj3?kajsldfj34uoj3rlkas"; // Example pepper value.

    /**
     * Constructor to initialize the server with specified security settings.
     * @param hashAlgorithm Hashing algorithm to be used.
     * @param isPepperEnabled Pepper enabled flag.
     */
    public Server(HashAlgorithm hashAlgorithm, boolean isPepperEnabled) {
        this.accounts = new HashMap<>();
        this.pendingTOTPAccounts = new HashMap<>();
        this.hashAlgorithm = hashAlgorithm;
        this.isPepperEnabled = isPepperEnabled;
    }

    /**
     * Registers a new user account with the server.
     * @param username The username for the new account.
     * @param password The password for the new account.
     * @param enableTOTP Flag indicating if TOTP is enabled for this account.
     */
    public void register(String username, String password, boolean enableTOTP) {

        // Basic validation. TODO: can delete validation in AccountBuilder?
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty.");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }

        // Check for duplicate usernames.
        if (accounts.containsKey(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        // Create the account using AuthService.
        Account newAccount = AuthService.createAccount(
                username, password, enableTOTP, hashAlgorithm);

        // Store the account in the server's account list.
        accounts.put(username, newAccount);
    }

    public LoginState login(String username, String password) {
        return null; // TODO: implement.
    }




    public String getTOTPSecret(String username, String password) {
        // TODO: implement. Most login first, then if TOTP enabled, return secret.
        return null;
    }




}
