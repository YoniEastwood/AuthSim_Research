package com.matoalot.authsim.server;
import com.matoalot.authsim.ExperimentManager;
import com.matoalot.authsim.Logger.CsvLogger;
import com.matoalot.authsim.Logger.LogEntry;
import com.matoalot.authsim.model.CaptchaState;
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
    private final HashMap<String, CaptchaSession> pendingCaptchaAccounts; // Accounts pending CAPTCHA verification.
    private final HashAlgorithm hashAlgorithm; // Password hashing algorithm.

    private final boolean isPepperEnabled; // Flag indicating if pepper is used.
    private final String pepper = "akd3#$adf(oj3?kajsldfj34uoj3rlkas"; // Example pepper value.

    private final int attemptsUntilCAPTCHA; // 0 means system will not throw CAPTCHA.

    // Lock account after this many bad login attempts.
    // 0 means account lock disabled.
    private final int accountLockThreshold;
    private final int lockTimeMinutes; // Lock time in minutes after reaching bad login attempts threshold.

    private final int totpTriesUntilSessionLock; // Lock account for 1 TOTP session after this amount of TOTP tries.
    private final long captchaLatencyMS; // Simulate CAPTCHA time to authenticate.

    private final CsvLogger logger; // Logger for logging attempts.

    private int totalLoginAttempts = 0; // Total login attempts counter.

    /**
     * Constructor to initialize the server with specified security settings.
     * @param hashAlgorithm Hashing algorithm to be used.
     * @param isPepperEnabled Pepper enabled flag.
     * @param attemptsUntilCAPTCHA Number of failed attempts before CAPTCHA is required.
     * @param accountLockThreshold Number of failed attempts before account is locked.
     * @param lockTimeMinutes Duration in minutes for which the account remains locked.
     * @param totpTriesUntilSessionLock Number of TOTP attempts before session lock
     * @param captchaLatencyMS Simulated latency for CAPTCHA verification in milliseconds.
     */
    public Server(
            HashAlgorithm hashAlgorithm, boolean isPepperEnabled, int attemptsUntilCAPTCHA, int accountLockThreshold,
            int lockTimeMinutes, int totpTriesUntilSessionLock, long captchaLatencyMS, CsvLogger logger

    ) {
        if (attemptsUntilCAPTCHA < 0) {
            throw new IllegalArgumentException("Attempts until CAPTCHA thrown cannot be negative");
        }
        this.attemptsUntilCAPTCHA = attemptsUntilCAPTCHA;

        if (accountLockThreshold < 0) {
            throw new IllegalArgumentException("Account lock threshold cannot be negative");
        }
        this.accountLockThreshold = accountLockThreshold;

        if (lockTimeMinutes < 0) {
            throw new IllegalArgumentException("Lock time minutes cannot be negative");
        }
        this.lockTimeMinutes = lockTimeMinutes;

        if (totpTriesUntilSessionLock < 1) {
            throw new IllegalArgumentException("TOTP tries until session lock must be at least 1");
        }
        this.totpTriesUntilSessionLock = totpTriesUntilSessionLock;

        if (captchaLatencyMS < 0) {
            throw new IllegalArgumentException("CAPTCHA latency cannot be negative");
        }
        this.captchaLatencyMS = captchaLatencyMS;

        if (logger == null) {
            throw new IllegalArgumentException("Logger cannot be null");
        }

        this.accounts = new HashMap<>();
        this.pendingTOTPAccounts = new HashMap<>();
        this.pendingCaptchaAccounts = new HashMap<>();
        this.hashAlgorithm = hashAlgorithm;
        this.isPepperEnabled = isPepperEnabled;
        this.logger = logger;
    }

    /**
     * Registers a new user account with the server.
     * @param username The username for the new account.
     * @param password The password for the new account.
     */
    public RegisterState register(String username, String password) {
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


        // Password structure validation.
        if (password.length() < 4 || password.length() > 20) {
            return RegisterState.FAILURE_INVALID_LENGTH;
        }


        // If pepper is being used add it.
        password = addPepperIfUsed(password);

        // Create the account using AuthService.
        Account newAccount = AuthService.createAccount(
                username, password, hashAlgorithm);

        // Store the account in the server's account list.
        accounts.put(username, newAccount);

        return RegisterState.SUCCESS;
    }


    /**
     * This serves as a log in function.
     * @param username Username.
     * @param password Password.
     * @return Log in state.
     */
    public LoginState login(String username, String password) {
        Instant instant = Instant.now(); // Timestamp of the attempt.
        long startTime = System.currentTimeMillis(); // Start time for latency calculation.
        LoginState state = LoginState.FAILURE_UNKNOWN; // Default state.
        int attemptNumber = 0;
        Account account = null;

        totalLoginAttempts += 1; // Increase total login attempts.

        try {
            if (username == null || password == null ||
                username.isBlank() || password.isBlank()) {
                state = LoginState.FAILURE_BAD_CREDENTIALS;
                return state;
            }

            // Remove white spaces.
            username = username.strip();
            password = password.strip();

            // Get the account Object
            account = accounts.get(username);

            // Add attempt to CAPTCHA session.
            AddAttemptToCaptchaList(username);
            if (attemptsUntilCAPTCHA > 0 &&
                    pendingCaptchaAccounts.get(username).shouldThrowCAPTCHA(attemptsUntilCAPTCHA)) {
                state = LoginState.FAILURE_REQUIRE_CAPTCHA;
                return state;
            }


            // If account does not exist, return fad credentials flag.
            if (account == null) {
                state = LoginState.FAILURE_BAD_CREDENTIALS;
                return state;
            }

            // If account is locked, return account locked flag.
            if (account.isAccountLocked()) {
                state = LoginState.FAILURE_ACCOUNT_LOCKED;
                return state;
            }

            // Get the attempt number for logging.
            attemptNumber = account.getBadLoginAttemptsCounter() + 1;

            // Apply pepper if used.
            String pepperedPassword = addPepperIfUsed(password);

            // Password is wrong, return failure.
            if (!AuthService.authenticatePassword(account, pepperedPassword, hashAlgorithm)) {
                state = LoginState.FAILURE_BAD_CREDENTIALS;

                // Increase bad login attempts counter.
                account.badLoginAttemptsIncreaser();
                lockAccountIfNeeded(account);

                return state;
            } else {
                // Successful login, reset bad login attempts counter.
                account.resetAttemptLoginCounter();
            }


            // Add user to TOTP waiting list only if he is not waiting for TOTP already.
            // If he is waiting for TOTP, do not reset the session.
            if (account.isUsingTOTP()) {
                pendingTOTPAccounts.putIfAbsent(username, new TotpSession(account));
                state = LoginState.FAILURE_TOTP_REQUIRED;
                return state;
            }

            // All test passed, user has logged in.
            // Reset CAPTCHA challenges for this user.
            pendingCaptchaAccounts.remove(username);
            account.resetAttemptLoginCounter(); // Reset bad login attempts counter.
            return LoginState.SUCCESS;

        } finally { // Log the attempt regardless of outcome.
            logAttempt(
                    instant.toString(),
                    (username == null) ? "null" : username,
                    hashAlgorithm.toString(),
                    (password == null) ? "null" : password,
                    state,
                    getProtectionFlags(account),
                    attemptNumber,
                    (int)(System.currentTimeMillis() - startTime), String.valueOf(ExperimentManager.GROUP_SEED)
            );
        }
    }


    /**
     * After login, verifies the TOTP code for the given username.
     * @param username Username.
     * @param attemptTOTP TOTP code attempt.
     * @return TOTP verification state.
     */
    public LoginState verifyTOTP(String username, String attemptTOTP) {
        Instant instant = Instant.now();
        long startTime = System.currentTimeMillis();
        LoginState state = LoginState.FAILURE_UNKNOWN;
        int attemptNumber = 0;
        Account account = null;

        totalLoginAttempts += 1; // Increase total login attempts.

        try {
            // If username is not pending verification, return failure.
            if (username == null || !pendingTOTPAccounts.containsKey(username.strip())) {
                state = LoginState.FAILURE_TOTP_INVALID;
                return state;
            }

            // Basic attemptTOTP check before proceeding.
            if (attemptTOTP == null) {
                state = LoginState.FAILURE_TOTP_INVALID;
                return state;
            }

            // Remove white spaces.
            attemptTOTP = attemptTOTP.strip();
            username = username.strip();

            // Get the totp session.
            account = accounts.get(username);
            TotpSession totpSession = pendingTOTPAccounts.get(username);

            // If account lock, quit.
            if (account.isAccountLocked()) {
                state = LoginState.FAILURE_ACCOUNT_LOCKED;
                return state;
            }

            // If user tried too much key, lock him for this session.
            if (totpSession.attempts >= totpTriesUntilSessionLock) {
                // Lock account for this session.
                account.lockAccountUntil(Instant.now().plus(30, ChronoUnit.SECONDS));
                // Reset the attempts.
                totpSession.resetTries();
                state = LoginState.FAILURE_ACCOUNT_LOCKED;
                return state;
            }

            // Verify TOTP.
            boolean successfulLogin = TOTPUtil.verify(account.getSecretTOTP(), attemptTOTP);


            if (successfulLogin) {
                // Remove from waiting TOTP login.
                pendingTOTPAccounts.remove(username);
                state = LoginState.SUCCESS;
                return state;
            }

            // Unsuccessful login
            totpSession.addAttempt(); // Record attempt.
            state = LoginState.FAILURE_TOTP_INVALID;
            return state;

        } finally {
            logAttempt(
                    instant.toString(),
                    (username == null) ? "null" : username,
                    "TOTP",
                    (attemptTOTP == null) ? "null" : attemptTOTP,
                    state,
                    getProtectionFlags(account),
                    attemptNumber,
                    (int)(System.currentTimeMillis() - startTime),
                    String.valueOf(ExperimentManager.GROUP_SEED)
            );
        }
    }

    /**
     * verifies the CAPTCHA test for the given username.
     * @param username  Username attempting to verify CAPTCHA.
     * @param attemptCaptchaToken CAPTCHA token provided by the user.
     * @return CAPTCHA verification state.
     */
    public CaptchaState verifyCAPTCHA(String username, String attemptCaptchaToken) {

        // Simulate the CAPTCHA test time.
        try {
            Thread.sleep(captchaLatencyMS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Basic null checks.
        if (username == null || attemptCaptchaToken == null) {
            return CaptchaState.FAILURE_INCORRECT_CAPTCHA;
        }
        // Remove white spaces.
        username = username.strip();
        attemptCaptchaToken = attemptCaptchaToken.strip();


        CaptchaState result;

        if (attemptCaptchaToken.equals(generateCPATCHA(username))){ // Correct CAPTCHA
            pendingCaptchaAccounts.remove(username); // Remove from pending CAPTCHA sessions.
            result = CaptchaState.SUCCESS;
        } else { // Incorrect CAPTCHA
            result = CaptchaState.FAILURE_INCORRECT_CAPTCHA;
        }

        return result;

        // Can add logging for CAPTCHA if needed in the future.
    }


    /**
     * Enables TOTP for a user if credentials are valid and returns the TOTP secret.
     * If user already has TOTP enabled, returns null for security reasons.
     * @param username The username of the account.
     * @param password The password of the account.
     * @return The TOTP secret if credentials are valid; otherwise, null.
     */
    public String enableTOTPForUser(String username, String password) {
        // If user does not exist or bad credentials, return null.
        if (login(username, password) != LoginState.SUCCESS) {
            return null; // Invalid credentials.
        }

        // Get the account.
        Account account = accounts.get(username);
        if (account == null) {
            throw new IllegalStateException("Account should exist after successful login.");
        }

        // If TOTP is already enabled, return null for security reasons.
        if (account.isUsingTOTP()) {
            return null;
        }

        // Generate TOTP secret and enable TOTP for the account.
        String totpSecret = TOTPUtil.generateSecret();
        account.enableTOTP(totpSecret);

        return totpSecret;
    }


    /**
     * Returns a string describing the protection flags for the given account and system.
     * @param account The account to check.
     * @return A string describing the protection mechanisms in place.
     */
    private String getProtectionFlags(Account account) {
        if (account == null) {
            return "Account does not exist. No protections.";
        }

        // Salt is always enabled in our system.
        String result = "Salt";

        if (isPepperEnabled) {
            result += " + Pepper";
        }

        if (attemptsUntilCAPTCHA > 0) {
            result += " + CAPTCHA required after " + attemptsUntilCAPTCHA + " attempts";
        }

        if (accountLockThreshold > 0) {
            result += " + Account locks after " + accountLockThreshold + " bad attempts for " + lockTimeMinutes + " minutes";
        }

        if (account.isUsingTOTP()) {
            result += " + TOTP enabled";
            result += " + TOTP session lock after " + totpTriesUntilSessionLock + " bad attempts";
        }

        return result;
    }

    /**
     * Logs an authentication attempt.
     * @param timestamp // Timestamp of the attempt.
     * @param username // Username being targeted.
     * @param hashMode // Type of hash being attacked.
     * @param guess // The guessed password.
     * @param resultState // Result of the attempt (e.g., SUCCESS, FAILURE).
     * @param protectionFlags // Protection mechanisms in place (e.g., CAPTCHA, TOTP).
     * @param userAttemptNumber // Number of attempts for this user.
     * @param latencyMS // Latency in milliseconds until response.
     * @param groupSeed // The seed of the group this project belongs to.
     */
    private void logAttempt(
            String timestamp, String username, String hashMode, String guess, LoginState resultState,
            String protectionFlags, int userAttemptNumber, int latencyMS, String groupSeed
    ) {
        // Create a logEntry on the attempt log in.
        LogEntry entry = new LogEntry(
                timestamp, username, hashMode, guess, resultState.toString(), protectionFlags, userAttemptNumber,
                totalLoginAttempts, latencyMS, String.valueOf(groupSeed)
        );

        // Add it to the log list.
        logger.log(entry);
    }

    /**
      If locking is enabled, lock the account if reached threshold.
        * @param account Account to check and lock if needed.
     */
    private void lockAccountIfNeeded(Account account) {
        if (accountLockThreshold == 0) {
            return; // Account lock disabled.
        }

        if (account.getBadLoginAttemptsCounter() >= accountLockThreshold) {
            // Reset bad login attempts counter.
            account.resetAttemptLoginCounter();

            // Lock account for server default minute.
            account.lockAccountUntil(
                    Instant.now().plus(lockTimeMinutes, ChronoUnit.MINUTES)
            );
        }
    }

    /**
     * Returns a simple CAPTCHA token verifier.
     * @param username username requesting CAPTCHA.
     * @return CAPTCHA token verifier.
     */
    public String generateCPATCHA(String username) {
        if(username == null) {
            return "null" + ExperimentManager.GROUP_SEED;
        }

        return username + ExperimentManager.GROUP_SEED;
    }

    /**
     * Adds an attempt to the CAPTCHA session for the given username.
     * @param username The username attempting to log in.
     */
    private void AddAttemptToCaptchaList(String username) {
        if (attemptsUntilCAPTCHA == 0) {
            return; // CAPTCHA disabled.
        }
        // Add attempt to CAPTCHA session.
        pendingCaptchaAccounts.putIfAbsent(username, new CaptchaSession(username));
        pendingCaptchaAccounts.get(username).addAttempt();
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
     * This keeps track of the attempts to decide when to lock the account for the session.
     */
    private static class TotpSession {
        Account account;
        int attempts; // TOTP attempts login.

        TotpSession(Account account) {
            this.account = account;
            this.attempts = 0;
        }

        void addAttempt() {
            this.attempts += 1;
        }

        /**
         * Restes the attempts of TOTP login.
         * Call after account locked for the session reset attempts.
         */
        void resetTries() {
            attempts = 0;
        }
    }

    /**
     * Private class to that represents a username trying to log in.
     * This keeps track of the attempts to decide when to throw CAPTCHA.
     */
    private static class CaptchaSession {
        String username; // Username that is trying to log in.
        int attempts; // Attempts log in.

        CaptchaSession(String username) {
            this.username = username;
            this.attempts = 0;
        }

        /**
         * Checks if CAPTCHA should be thrown.
         * @param attemptsUntilCAPTCHA Threshold of attempts until CAPTCHA is thrown.
         * @return True if CAPTCHA should be thrown.
         */
        boolean shouldThrowCAPTCHA(int attemptsUntilCAPTCHA) {
            return attempts >= attemptsUntilCAPTCHA;
        }
        /**
         * Increases the attempts login.
         */
        void addAttempt() {
            this.attempts += 1;
        }
    }
}
