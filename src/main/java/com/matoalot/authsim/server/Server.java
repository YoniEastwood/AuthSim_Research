package com.matoalot.authsim.server;
import com.matoalot.authsim.ExperimentManager;
import com.matoalot.authsim.Logger.LogEntry;
import com.matoalot.authsim.Logger.LoggerManager;
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

    private static final int ACCOUNT_LOCK_THRESHOLD = 5; // Lock account after this many bad login attempts.
    private static final int LOCK_TIME_MINUTES = 5; // Lock time in minutes after reaching bad login attempts threshold.
    private final int TOTP_TRIES_UNTIL_SESSION_LOCK = 3; // Lock account for 1 TOTP session after this amount of TOTP tries.
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
        this.pendingCaptchaAccounts = new HashMap<>();
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


        // Password structure validation.
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

        try {
            if (username == null || password == null ||
                username.isBlank() || password.isBlank()) {
                state = LoginState.FAILURE_BAD_CREDENTIALS;
                return state;
            }

            // Remove white spaces.
            username = username.strip();
            password = password.strip();

            // Add attempt to CAPTCHA session.
            AddAttemptToCaptchaList(username);
            if (attemptsUntilCAPTCHA > 0 &&
                    pendingCaptchaAccounts.get(username).shouldThrowCAPTCHA(attemptsUntilCAPTCHA)) {
                state = LoginState.FAILURE_REQUIRE_CAPTCHA;
                return state;
            }


            // Get the account Object
            Account account = accounts.get(username);

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
            password = addPepperIfUsed(password);

            // Password is wrong, return failure.
            if (!AuthService.authenticatePassword(account, password, hashAlgorithm)) {
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
            if (account.isUsingTOTP() && !pendingTOTPAccounts.containsKey(username)) {
                pendingTOTPAccounts.put(username, new TotpSession(account));
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
                    "Implement this",  // TODO: Implement protection flags.
                    attemptNumber,
                    (int)(System.currentTimeMillis() - startTime), String.valueOf(ExperimentManager.GROUP_SEED)
            );
        }
    }


    /**
     * After log in, users may need to
     * @param username
     * @param attemptTOTP
     * @return
     */
    public LoginState verifyTOTP(String username, String attemptTOTP) {
        Instant instant = Instant.now();
        long startTime = System.currentTimeMillis();
        LoginState state = LoginState.FAILURE_UNKNOWN;
        int attemptNumber = 0;

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

            // Get the account.
            Account account = accounts.get(username);
            TotpSession totpSession = pendingTOTPAccounts.get(username);

            // If account lock, quit.
            if (account.isAccountLocked()) {
                state = LoginState.FAILURE_ACCOUNT_LOCKED;
                return state;
            }

            // If user tried too much key, lock him for this session.
            if (totpSession.attempts >= TOTP_TRIES_UNTIL_SESSION_LOCK) {
                // Lock account for this session.
                account.lockAccountUntil(
                        Instant.now().plus(30, ChronoUnit.SECONDS)
                );
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
            totpSession.attempts += 1; // Record attempt.
            state = LoginState.FAILURE_TOTP_INVALID;
            return state;

        } finally {
            logAttempt(
                    instant.toString(),
                    (username == null) ? "null" : username,
                    "TOTP",
                    (attemptTOTP == null) ? "null" : attemptTOTP,
                    state,
                    "Implement this",  // TODO: Implement protection flags.
                    attemptNumber,
                    (int)(System.currentTimeMillis() - startTime),
                    String.valueOf(ExperimentManager.GROUP_SEED)
            );
        }
    }

    /**
     * verifies the CAPTCHA test for the given username.
     * @param username // Username attempting to verify CAPTCHA.
     * @param attemptCaptchaToken // CAPTCHA token provided by the user.
     * @return CAPTCHA verification state.
     */
    public CaptchaState verifyCAPTCHA(String username, String attemptCaptchaToken) {
        long startTime = System.currentTimeMillis();

        // Simulate the CAPTCHA test time.
        try {
            Thread.sleep(CAPTCHA_LATENCY_MS);
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

        // Log the CAPTCHA attempt.
        // TODO: Implement logging for CAPTCHA attempts if needed.
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
                LoggerManager.getLogs().size() + 1, latencyMS, String.valueOf(groupSeed)
        );

        // Add it to the log list.
        LoggerManager.addLog(entry);
    }

    /**
     *
     */
    private void lockAccountIfNeeded(Account account) {
        if (account.getBadLoginAttemptsCounter() >= ACCOUNT_LOCK_THRESHOLD) {
            // Lock account for server default minute.
            account.lockAccountUntil(
                    Instant.now().plus(LOCK_TIME_MINUTES, ChronoUnit.MINUTES)
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
