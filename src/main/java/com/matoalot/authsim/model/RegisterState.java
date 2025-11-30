package com.matoalot.authsim.model;

public enum RegisterState {
    SUCCESS, // Successful registration
    FAILURE_USERNAME_EXISTS,
    FAILURE_INVALID_LENGTH,
    FAILURE_WEAK_PASSWORD
}
