package com.matoalot.authsim.server;
import com.matoalot.authsim.ExperimentManager;
import com.matoalot.authsim.model.HashAlgorithm;
import com.matoalot.authsim.model.LoginState;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;

import com.matoalot.authsim.model.RegisterState;
import com.matoalot.authsim.utils.TOTPUtil;

/**
 * Server class that manages user accounts and authentication settings.
 */
public class Server {
    private final HashMap<String, Account> accounts; // List of user accounts.
    private final HashMap<String, TotpSession> pendingTOTPAccounts; // Accounts pending TOTP verification.
    private final HashAlgorithm hashAlgorithm; // Password hashing algorithm.

    private final boolean isPepperEnabled; // Flag indicating if pepper is used.
    private final String pepper = "akd3#$adf(oj3?kajsldfj34uoj3rlkas"; // Example pepper value.

    private final int attemptsUntilCAPTCHA; // 0 means system will not throw CAPTCHA.

    private static final int TOTP_TRIES_UNTIL_SESSION_LOCK = 3; // Lock account for 1 TOTP session after this amount of TOTP tries.

    private static final long CAPTCHA_LATENCY_MS = 50; // Simulate CAPTCHA time to authenticate.


    /**
     * Constructor to initialize the server with specified security settings.
     * @param hashAlgorithm Hashing algorithm to be used.
     * @param isPepperEnabled Pepper enabled flag.
     */
    public Server(HashAlgorithm hashAlgorithm, boolean isPepperEnabled, int attemptsUntilCAPTCHA) {
        if (attemptsUntilCAPTCHA < 0) {
            throw new IllegalArgumentException("Attempts until CAPTCHA thrown cannot be negative");
        }
        this.attemptsUntilCAPTCHA = attemptsUntilCAPTCHA;

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
    public RegisterState register(String username, String password, boolean enableTOTP) {

        // Check not null arguments
        if (username == null || password == null) {
            return RegisterState.FAILURE_INVALID_LENGTH;
        }

        // Remove white spaces.
        username = username.strip();
        password = password.strip();

        // Validate username.
        if (username.length() < 4 || username.strip().length() > 20) {
            return RegisterState.FAILURE_INVALID_LENGTH;
        }
        // Check for duplicate usernames.
        if (accounts.containsKey(username)) {
            return RegisterState.FAILURE_USERNAME_EXISTS;
        }


        // Password validation.
        if (password.length() < 4 || password.length() > 20) {
            return RegisterState.FAILURE_INVALID_LENGTH;
        }

        // If pepper is being used add it.
        password = addPepperIfUsed(password);


        // Create the account using AuthService.
        Account newAccount = AuthService.createAccount(
                username, password, enableTOTP, hashAlgorithm);

        // Store the account in the server's account list.
        accounts.put(username, newAccount);

        return RegisterState.SUCCESS;
    }



    public LoginState login(String username, String password) {
        if (username == null || password == null) {
             return LoginState.FAILURE_BAD_CREDENTIALS;
        }

        // Remove white spaces.
        username = username.strip();
        password = password.strip();

        // Get the account Object
        Account account = accounts.get(username);

        // If account does not exist, return fad credentials flag.
        // NOTE: In real production I would throw also CAPTCHA for bad usernames attempts
        // so the attacker wouldn't use it to find valid usernames.
        if (account == null) {
            return LoginState.FAILURE_BAD_CREDENTIALS;
        }

        // Throw CAPTCHA if needed.
        if(shouldThrowCAPTCHA(account)) {
            return LoginState.FAILURE_REQUIRE_CAPTCHA;
        }

        // Apply pepper if used.
        password = addPepperIfUsed(password);

        // Password is wrong, return failure.
        if (AuthService.authenticatePassword(account, password, hashAlgorithm)) {
            return LoginState.FAILURE_BAD_CREDENTIALS;
        }

        // Add user to TOTP waiting list only if he is not waiting for TOTP already.
        if (account.isUsingTOTP() && !pendingTOTPAccounts.containsKey(username)) {
            pendingTOTPAccounts.put(username, new TotpSession(account));
            return LoginState.FAILURE_TOTP_REQUIRED;
        }

        // All test passed, user has logged in.
        return LoginState.SUCCESS;
    }

    public LoginState verifyTOTP(String username, String attemptTOTP) {
        // If username is not pending verification, return failure.
        if (username == null || !pendingTOTPAccounts.containsKey(username.strip())) {
            return LoginState.FAILURE_TOTP_INVALID;
        }

        // Basic captcha check before proceeding.
        if (attemptTOTP == null) {
            return LoginState.FAILURE_TOTP_INVALID;
        }

        // Remove white spaces.
        attemptTOTP = attemptTOTP.strip();
        username = username.strip();

        // Get the account.
        Account account = accounts.get(username);
        TotpSession totpSession = pendingTOTPAccounts.get(username);

        // If account lock, quit.
        if (account.isAccountLocked()) {
            return LoginState.FAILURE_ACCOUNT_LOCKED;
        }

        // If user tried too much key, lock him for this session.
        if (totpSession.attempts >= TOTP_TRIES_UNTIL_SESSION_LOCK) {
            // Lock account for this session.
            account.lockAccountUntil(
                    Instant.now().plus(30, ChronoUnit.SECONDS)
            );
            // Reset the attempts.
            totpSession.resetTries();
            return LoginState.FAILURE_ACCOUNT_LOCKED;
        }

        // Verify the CAPTCHA.
        boolean successfulLogin = TOTPUtil.verify(account.getSecretTOTP(), attemptTOTP);


        if (successfulLogin) {
            // Remove from waiting TOTP login.
            pendingTOTPAccounts.remove(username);
            return LoginState.SUCCESS;
        }

        // Unsuccessful login
        totpSession.attempts += 1; // Record attempt.
        return LoginState.FAILURE_TOTP_INVALID;
    }

    public LoginState loginWithCAPTCHA(String username, String password, String captchaToken) {
        // Simulate the CAPTCHA test time.
        try {
            Thread.sleep(CAPTCHA_LATENCY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // If CAPTCHA verifies, continue to log in method.
        if (captchaToken.equals(generateCPATCHA(username))) {
            return login(username, password);
        }

        // CAPTCHA didn't pass
        return LoginState.FAILURE_CAPTCHA_INVALID;
    }


    /**
     * Retruns a simple CAPTCHA token verifier.
     * @param username username requesting CAPTCHA.
     * @return CAPTCHA token verifier.
     */
    public String generateCPATCHA(String username) {
        return username + ExperimentManager.GROUP_SEED;
    }


    /**
     * Helper method to decide if CAPTCHA should be thrown.
     * @param account account to test for
     * @return True if login attempts should return CAPTCHA.
     */
    private boolean shouldThrowCAPTCHA(Account account) {
        if (attemptsUntilCAPTCHA == 0) { // System is not using CAPTCHA.
            return false;
        }
        if (account.getBadLoginAttemptsCounter() >= attemptsUntilCAPTCHA) {
            return true;
        }
        return false;
    }


    /**
     * Adds pepper to the password if pepper is used.
     * @param password password to add the pepper.
     * @return Password with pepper.
     */
    private String addPepperIfUsed(String password) {
        if (isPepperEnabled) {
            return password + pepper;
        }
        return password;
    }


    /**
     * Private class to that represents account that is waiting for TOTP.
     */
    private static class TotpSession {
        Account account;
        int attempts; // TOTP attempts login.

        TotpSession(Account account) {
            this.account = account;
            this.attempts = 0;
        }

        /**
         * Restes the attempts of TOTP login.
         * Call after account locked for the session reset attempts.
         */
        void resetTries() {
            attempts = 0;
        }
    }
}
