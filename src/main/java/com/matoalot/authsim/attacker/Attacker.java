package com.matoalot.authsim.attacker;

import com.matoalot.authsim.model.LoginState;
import com.matoalot.authsim.server.Server;
import com.matoalot.authsim.utils.PasswordGenerator;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.PriorityQueue;
import java.util.concurrent.TimeUnit;


public class Attacker {
    public static final int PAUSE_ATTACK_ON_LOCK_MINUTES = 1; // Pause time on all accounts lock.

    private final Server server; // Server to attack.
    private final List<String> targetUsernames; // List of target usernames.
    private final long maxRunTimeMS; // Maximum runtime in milliseconds.
    private final int maxAttempts; // Maximum attempts for the attack.
    private int globalAttempts = 0; // Global attempts counter.
    private long startTime; // Attack start time.

    private long lastProgressBarUpdateTime = 0; // Last time the progress bar was updated.



    public Attacker(Server server, List<String> targetUsernames, int maxRunTimeMinuets, int maxAttempts) {
        // Basic validations.
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("maxAttempts must be greater than 0");
        }
        if (maxRunTimeMinuets <= 0) {
            throw new IllegalArgumentException("maxRunTimeMS must be greater than 0");
        }
        if (targetUsernames == null || targetUsernames.isEmpty()) {
            throw new IllegalArgumentException("TargetUsernames must not be null or empty");
        }
        if (server == null) {
            throw new IllegalArgumentException("Server is null");
        }

        this.server = server;
        this.maxRunTimeMS = TimeUnit.MINUTES.toMillis(maxRunTimeMinuets);// Convert minuets to milliseconds.
        this.maxAttempts = maxAttempts;
        this.globalAttempts = 0;
        this.targetUsernames = targetUsernames;
    }



    public void launchAttack() {
        this.startTime = System.currentTimeMillis(); // Record start time.

        System.out.println("---Attacker started---");

        // Run the spraying attack first and save the survived usernames for bruteforce attack.
        List<String> breachedAccounts;
        breachedAccounts = launchSprayingAttack(targetUsernames);

        // Create a Priority Queue for accounts that survived spraying attack.
        // The queue is ordered by account lock time.
        PriorityQueue<AccountUnderAttack> queue = new PriorityQueue<>();
        for (String username : targetUsernames) {
            // if username was not breached in spraying attack, add to queue for bruteforce attack.
            if (!breachedAccounts.contains(username)) {
                queue.add(new AccountUnderAttack(username));
            }
        }



        // Launch the bruteforce attack on the remaining accounts.
        System.out.println("\r\n---Starting Bruteforce Attack on remaining accounts---\n");
        launchBruteforceAttack(queue);

        System.out.println("\n---Attacker finished---" );
    }


    /**
     * Launch a bruteforce attack on accounts in the priority queue.
     * Prioritizes accounts based on their lock time.
     * Attacks all accounts fairly.
     * @param queue Priority queue of accounts to attack.
     */
    private void launchBruteforceAttack(PriorityQueue<AccountUnderAttack> queue) {
        final int ATTEMPTS_PER_ACCOUNT = 3000; // Number of attempts per account before moving to the next.
        int attemptsOnCurrentAccount = 0; // Attempts counter for the current account.

        // Pull an account from the queue.
        AccountUnderAttack account = queue.poll();
        if (account == null) { // No more accounts to attack.
            System.out.println("\rNo more accounts to attack. Ending bruteforce attack.");
            printProgressBar(globalAttempts, maxAttempts);
            return;
        }

        // While we have not exceeded time or attempts limits.
        while (!(isTimeExceeded() || isMaxAttemptsExceeded()) && account != null) {
            if (System.currentTimeMillis() - lastProgressBarUpdateTime > 1000) { // Update progress bar every Second.
                lastProgressBarUpdateTime = System.currentTimeMillis();
                printProgressBar(globalAttempts, maxAttempts);
            }

            // Attempt to log in with the next password.
            String password = account.nextPassword();
            if (password == null) { // No more passwords to try for this account.
                System.out.println("\rExhausted all passwords for username: " + account.getUsername() + ". Ending attack on this account.");
                printProgressBar(globalAttempts, maxAttempts);
                continue; // Move to the next account. (don't re-add to queue)
            }

            LoginState loginState = server.login(account.getUsername(), password);
            globalAttempts++; // Increment global attempts.

            if (loginState == LoginState.FAILURE_REQUIRE_CAPTCHA) {
                System.out.println("\rCAPTCHA required for username: " + account.getUsername() + ". Verifying CAPTCHA...");
                printProgressBar(globalAttempts, maxAttempts);
                // Simulate CAPTCHA test.
                server.verifyCAPTCHA(account.getUsername(), server.generateCPATCHA(account.getUsername()));
                System.out.println("CAPTCHA verified for username: " + account.getUsername() + ". Retrying login...");
                printProgressBar(globalAttempts, maxAttempts);
                // Retry login after CAPTCHA.
                loginState = server.login(account.getUsername(), password);
                globalAttempts++;
            }

            attemptsOnCurrentAccount++; // Increment attempts on current account.

            switch (loginState) {
                case SUCCESS -> { // Account breached.
                    System.out.println("\rBreached account: " + account.getUsername() + " with password: " + password);
                    printProgressBar(globalAttempts, maxAttempts);
                    // Get next account from queue.
                    account = queue.poll();
                    attemptsOnCurrentAccount = 0; // Reset attempts counter for new account.
                }
                case FAILURE_BAD_CREDENTIALS ->  {
                    // Continue trying next password.
                    continue;
                }
                case FAILURE_ACCOUNT_LOCKED -> {
                    long lockUntil = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(PAUSE_ATTACK_ON_LOCK_MINUTES);
                    account.setLockedUntil(lockUntil);
                    System.out.println("\rAccount locked: " + account.getUsername() + ". Will retry again in " + PAUSE_ATTACK_ON_LOCK_MINUTES + " minutes....");
                    printProgressBar(globalAttempts, maxAttempts);
                    // Re-add account to queue for further attempts after lock period.
                    queue.add(account);
                    // Get next account from queue.
                    account = queue.poll();
                    attemptsOnCurrentAccount = 0; // Reset attempts counter for new account.
                }
                case FAILURE_REQUIRE_CAPTCHA -> {
                    System.err.println("\rWarning: CAPTCHA requirement should have been handled already for username: " + account.getUsername());
                    printProgressBar(globalAttempts, maxAttempts);
                }
                case FAILURE_TOTP_REQUIRED -> {
                    System.out.println("\rFound password for TOTP protected account: " + account.getUsername() + " with password: " + password);
                    System.out.println("Due to TOTP protection strength, cannot breach this account in a reasonable amount of time.");
                    printProgressBar(globalAttempts, maxAttempts);
                    // Get next account from queue.
                    account = queue.poll();
                    attemptsOnCurrentAccount = 0; // Reset attempts counter for new account.
                }
                default -> {
                    // Not expected. Log for further analysis.
                    System.err.println("\rWarning: Unexpected login state for username: " + account.getUsername() + " with password: " + password + ". State: " + loginState);
                    printProgressBar(globalAttempts, maxAttempts);
                    // Re-add account to queue for further attempts.
                    queue.add(account);
                }
            } // End of switch case

            // If we have reached the attempts limit for the current account, move to the next account.
            if (attemptsOnCurrentAccount >= ATTEMPTS_PER_ACCOUNT) {
                // Re-add current account to queue for further attempts later.
                // Not really locked, just to reorder.
                account.setLockedUntil(System.currentTimeMillis() + 1); // Push to the back of the queue.
                queue.add(account);
                // Get next account from queue.
                account = queue.poll();
                attemptsOnCurrentAccount = 0; // Reset attempts counter for new account.
            }

            if (account.isLocked()) {
                System.out.println("\rAll accounts are currently locked. Sleeping for " + PAUSE_ATTACK_ON_LOCK_MINUTES + " minutes...");
                printProgressBar(globalAttempts, maxAttempts);
                try {
                    TimeUnit.MINUTES.sleep(PAUSE_ATTACK_ON_LOCK_MINUTES);

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.err.println("\rSleep interrupted: " + e.getMessage());
                    printProgressBar(globalAttempts, maxAttempts);
                }
            }
        }

        // Log the reason for ending the attack.
        if (account == null) {
            System.out.println("\rNo more accounts to attack. Ending bruteforce attack.");
            printProgressBar(globalAttempts, maxAttempts);
        } else {
            System.out.println("\rAttack time or attempts limit reached. Ending bruteforce attack.");
            printProgressBar(globalAttempts, maxAttempts);
        }
    }


    /**
     * Launch a password spraying attack.
     * @param targetUsernames List of target usernames.
     * @return List of usernames that their account was breached.
     */
    private List<String> launchSprayingAttack(List<String> targetUsernames) {
        targetUsernames = new ArrayList<>(targetUsernames); // Copy to avoid modifying the original list.
        List<String> breachedAccountsPassword = new ArrayList<>(); // List of usernames where their password was found.

        // For each common password, attempt to log in for each username.
        for (String commonPassword : PasswordGenerator.COMMON_PASSWORDS_LIST) {

            // Create an iterator for the target usernames.
            Iterator<String> targetUsernamesIterator = targetUsernames.iterator();

            // Iterate over usernames.
            while (targetUsernamesIterator.hasNext()) {
                String username = targetUsernamesIterator.next(); // Get current username.

                if (System.currentTimeMillis() - lastProgressBarUpdateTime > 1000) { // Update progress bar every second.
                    lastProgressBarUpdateTime = System.currentTimeMillis();
                    printProgressBar(globalAttempts, maxAttempts);
                }

                // If max attempts or time exceeded, return the survived usernames.
                if (isTimeExceeded() || isMaxAttemptsExceeded()) {
                    System.out.println("\rAttack time or attempts limit reached. Ending spraying attack.");
                    printProgressBar(globalAttempts, maxAttempts);
                    return targetUsernames;
                }

                // Attempt login.
                LoginState loginState = server.login(username, commonPassword);
                globalAttempts++; // Increment global attempts.

                // Need to verify CAPTCHA for this attempt.
                if (loginState == LoginState.FAILURE_REQUIRE_CAPTCHA) {
                    System.out.println("\rCAPTCHA required for username: " + username + ". Verifying CAPTCHA...");
                    printProgressBar(globalAttempts, maxAttempts);
                    // Simulate CAPTCHA test.
                    server.verifyCAPTCHA(username, server.generateCPATCHA(username));
                    System.out.println("\rCAPTCHA verified for username: " + username + ". Retrying login...");
                    printProgressBar(globalAttempts, maxAttempts);
                    // Retry login after CAPTCHA.
                    loginState = server.login(username, commonPassword);
                    globalAttempts++;
                }

                switch (loginState) {
                    case SUCCESS -> { // Account breached.
                        System.out.println("\rBreached account: " + username + " with password: " + commonPassword);
                        printProgressBar(globalAttempts, maxAttempts);
                        targetUsernamesIterator.remove(); // Remove breached account from target list.
                        breachedAccountsPassword.add(username); // Add to breached accounts list.
                    }
                    case FAILURE_BAD_CREDENTIALS ->  {
                        // Do nothing, just a failed attempt.
                    }
                    case FAILURE_ACCOUNT_LOCKED -> {
                        System.out.println("\rAccount locked: " + username + ". Skipping further password spraying on this account.");
                        printProgressBar(globalAttempts, maxAttempts);
                        targetUsernamesIterator.remove(); // Remove locked account from target list.
                    }
                    case FAILURE_TOTP_REQUIRED -> {
                        System.out.println("\rFound password for TOTP protected account: " + username + " with password: " + commonPassword);
                        System.out.println("Due to TOTP protection strength, cannot breach this account in a reasonable amount of time.");
                        printProgressBar(globalAttempts, maxAttempts);
                        targetUsernamesIterator.remove(); // Remove TOTP protected account from target list.
                        breachedAccountsPassword.add(username); // Add to breached accounts list.
                    }
                    default -> {
                        // Not expected. Log for further analysis.
                        System.err.println("\rWarning: Unexpected login state for username: " + username + " with password: " + commonPassword + ". State: " + loginState);
                        printProgressBar(globalAttempts, maxAttempts);
                    }
                } // End of switch case

            } // End of usernames loop
        } // End of common passwords loop

        // Return the list of breached accounts.
        return breachedAccountsPassword;
    }




    // Helper methods to check time and attempts limits.
    private boolean isTimeExceeded() {
        return (System.currentTimeMillis() - startTime) >= maxRunTimeMS;
    }
    // Helper methods to check attempts limits.
    private boolean isMaxAttemptsExceeded() {
        return globalAttempts >= maxAttempts;
    }

    /**
     * Updates the progress bar on the console.
     * @param current Current attempt count.
     * @param total Total max attempts.
     */
    private void printProgressBar(int current, int total) {
        // Progress bar width in characters.
        int width = 50;

        // Calculate percentage completed.
        float percent = (float) current / total;
        int completedChars = (int) (width * percent);

        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < width; i++) {
            if (i < completedChars) {
                bar.append("=");
            } else if (i == completedChars) {
                bar.append(">");
            } else {
                bar.append(" ");
            }
        }
        bar.append("]");

        // Calculate elapsed time.
        long elapsedTimeMS = System.currentTimeMillis() - startTime;
        int elapsedTimeMinutes = (int) (elapsedTimeMS / (1000.0 * 60.0));
        int TotalMinutes = (int) (maxRunTimeMS / (1000 * 60));
        double timePercent = (double) elapsedTimeMS / maxRunTimeMS;

        // Print the progress bar.
        System.out.print("\r" + bar.toString() + String.format(" %.2f%% (%d/%d) | Time: %.2f%% (%d/%d minutes)",
                percent * 100, current, total, timePercent * 100, elapsedTimeMinutes, TotalMinutes));

        System.out.flush();
    }


}