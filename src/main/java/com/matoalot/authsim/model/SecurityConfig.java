package com.matoalot.authsim.model;

/**
 * Model class representing a security configuration for an experiment.
 */
public class SecurityConfig {
    public String experimentId; // Unique identifier for the experiment
    public String description; // Description of the experiment
    public HashAlgorithm hashAlgorithm; // Hashing algorithm used.
    public boolean isPepperEnabled; // Flag for pepper usage.
    public boolean isTOTPEnabled; // Flag for TOTP usage.

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
               "\n  TOTP Enabled: " + isTOTPEnabled + "\n";
    }

}
