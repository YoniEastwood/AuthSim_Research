/**
 * A cube representing a line from the attack
 */

package com.matoalot.authsim.Logger;

public class LogEntry {
    public String groupSeed; // The seed of the group this project belongs to.
    public String timestamp; // Timestamp of the attempt.
    public String username; // Username being targeted.
    public String hashType; // Type of hash being attacked.
    public String guess; // The guessed password.
    public String result; // Result of the attempt (e.g., SUCCESS, FAILURE).
    public String protectionFlags; // Protection mechanisms in place (e.g., CAPTCHA, TOTP).
    public int userAttemptNumber; // Number of attempts for this user.
    public int globalAttemptNumber; // Total number of attempts across all users.
    public double latencyMS; // Latency in milliseconds until response.

    /**
     * Constructor for LogEntry
     * @param timestamp // Timestamp of the attempt.
     * @param username // Username being targeted.
     * @param hashType // Type of hash being attacked.
     * @param guess // The guessed password.
     * @param result // Result of the attempt (e.g., SUCCESS, FAILURE).
     * @param protectionFlags // Protection mechanisms in place (e.g., CAPTCHA, TOTP).
     * @param userAttemptNumber // Number of attempts for this user.
     * @param globalAttemptNumber // Total number of attempts across all users.
     * @param latencyMS // Latency in milliseconds until response.
     * @param groupSeed // The seed of the group this project belongs to.
     */
    public LogEntry(String timestamp, String username, String hashType, String guess, String result, String protectionFlags, int userAttemptNumber,int globalAttemptNumber, int latencyMS, String groupSeed) {
        this.timestamp = timestamp;
        this.username = username;
        this.hashType = hashType;
        this.guess = guess;
        this.result = result;
        this.protectionFlags = protectionFlags;
        this.userAttemptNumber = userAttemptNumber;
        this.globalAttemptNumber = globalAttemptNumber;
        this.latencyMS = latencyMS;
        this.groupSeed = groupSeed;
    }

}
