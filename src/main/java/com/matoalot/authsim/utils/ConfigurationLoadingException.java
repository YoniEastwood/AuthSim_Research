package com.matoalot.authsim.utils;

/**
 * Exception thrown when there is an error loading configuration.
 */
public class ConfigurationLoadingException extends RuntimeException {
    public ConfigurationLoadingException(String message) {
        super(message);
    }

    public ConfigurationLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}
