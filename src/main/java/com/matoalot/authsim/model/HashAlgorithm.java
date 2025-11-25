package com.matoalot.authsim.model;

import com.google.gson.annotations.SerializedName;

public enum HashAlgorithm {

    @SerializedName("SHA-256") // Easier to read in JSON
    SHA256,

    @SerializedName("BCrypt") // Easier to read in JSON
    BCRYPT,

    @SerializedName("Argon2id") // Easier to read in JSON
    ARGON2ID
}
