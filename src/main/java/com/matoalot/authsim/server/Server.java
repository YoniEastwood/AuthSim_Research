package com.matoalot.authsim.server;
import com.matoalot.authsim.model.HashAlgorithm;

import java.util.HashMap;

/**
 * Server class that manages user accounts and authentication settings.
 */
public class Server {
    private HashMap<String, Account> accounts; // List of user accounts.
    private HashMap<String, Account> pendingTOTPAccounts; // Accounts pending TOTP verification.
    private HashAlgorithm hashAlgorithm; // Password hashing algorithm.

    private boolean isPepperEnabled; // Flag indicating if pepper is used.
    private String pepper; // TODO: Implement pepper management and find the best way to store it securely.

    private boolean isSaltEnabled; // Flag indicating if salt is used.

    /**
     * Constructor to initialize the server with specified security settings.
     * @param hashAlgorithm Hashing algorithm to be used.
     * @param isPepperEnabled Pepper enabled flag.
     * @param isSaltEnabled Salt enabled flag.
     */
    public Server(HashAlgorithm hashAlgorithm, boolean isPepperEnabled, boolean isSaltEnabled) {
        this.accounts = new HashMap<>();
        this.pendingTOTPAccounts = new HashMap<>();
        this.hashAlgorithm = hashAlgorithm;
        this.isPepperEnabled = isPepperEnabled;
        this.isSaltEnabled = isSaltEnabled;
    }

    /**
     * Registers a new user account with the server.
     * @param username The username for the new account.
     * @param password The password for the new account.
     * @param isTOTPEnabled Flag indicating if TOTP is enabled for this account.
     */
    public void registerAccount(String username, String password, boolean isTOTPEnabled) {} // TODO: Implement.


}
