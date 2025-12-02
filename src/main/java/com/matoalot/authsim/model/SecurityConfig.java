package com.matoalot.authsim.model;

/**
 * Model class representing a security configuration for an experiment.
 */
public class SecurityConfig {
    public String experimentId; // Unique identifier for the experiment
    public String description; // Description of the experiment
    public HashAlgorithm hashAlgorithm; // Hashing algorithm used.
    public boolean isPepperEnabled; // Flag for pepper usage.
    public boolean isTOTPEnabled; // Flag for TOTP usage across all accounts.
    public int attemptsUntilCAPTCHA; // Number of failed attempts before CAPTCHA is enforced.
    public int accountLockThreshold; // Number of failed attempts before account lockout.
    public int lockTimeMinutes; // Duration of account lockout in minutes.
    public int totpTriesUntilSessionLock; // Number of TOTP failures before session lock.
    public int captchaLatencyMS; // Latency in milliseconds for CAPTCHA processing.



    public SecurityConfig() {}

    /**
     * String representation of the configuration.
     * @return Formatted string with configuration details.
     */
    @Override
    public String toString() {
        return "Exp #" + experimentId + ": " + description +
                "\n  Hash Algorithm: " + hashAlgorithm +
                "\n  Pepper Enabled: " + isPepperEnabled +
                "\n  Attempts Until CAPTCHA: " + attemptsUntilCAPTCHA +
                "\n  Account Lock Threshold: " + accountLockThreshold +
                "\n  Lock Time (minutes): " + lockTimeMinutes +
                "\n  TOTP Tries Until Session Lock: " + totpTriesUntilSessionLock +
                "\n  CAPTCHA Latency (ms): " + captchaLatencyMS + "\n";
    }

}
