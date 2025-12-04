package com.matoalot.authsim.attacker;

import java.util.Iterator;

/**
 * Iterator to generate all possible passwords of length 4 with characters (a-z),
 * and of length 6 with characters (a-z, 0-9).
 */
public class PasswordIterator implements Iterator<String> {
    public static final String CHARS_MEDIUM = "abcdefghijklmnopqrstuvwxyz"; // Chars for medium passwords.
    public static final int LENGTH_MEDIUM = 4; // Length for medium passwords.

    public static final String CHARS_STRONG = "abcdefghijklmnopqrstuvwxyz0123456789"; // Chars for strong passwords.
    public static final int LENGTH_STRONG = 6; // Length for strong passwords.

    private char[] charset; // Character set to use.
    private int length; // Password length.
    private int[] indices; // Current indices used to build the password.
    private boolean hasNext = true; // Flag to indicate if there are more passwords.

    /**
     * Constructor to initialize the iterator.
     */
    public PasswordIterator() {
        // Start with medium strength passwords by default.
        charset = CHARS_MEDIUM.toCharArray();
        length = LENGTH_MEDIUM;
        indices = new int[length]; // Initialize indices to zero.
    }

    /**
     * Check if there are more passwords to iterate over.
     * @return True if there are more passwords, false otherwise.
     */
    @Override
    public boolean hasNext() {
        return hasNext;
    }

    /**
     * Generate the next password in the sequence.
     * @return The next password as a string.
     */
    @Override
    public String next() {
        if (!hasNext) return null; // No more passwords.

        // Calculate the current password based on indices.
        StringBuilder sb = new StringBuilder();
        for (int i : indices) {
            sb.append(charset[i]);
        }
        String currentPassword = sb.toString();


        // Update indices for the next password.
        int i = length - 1; // Start from the index at the rightmost position.
        while (i >= 0) {
            indices[i]++; // Increment the current index.

            // If the current index is still within bounds, we are done.
            if (indices[i] < charset.length) {
                break;
            } else { // If the current index exceeds bounds.
                indices[i] = 0; // Reset current index to zero.
                i--; // Move to the next index to the left.
            }
        }

        // If we have moved past the leftmost index, we ran out of combinations.
        if (i < 0) {
            // If we are currently generating medium passwords, switch to strong passwords.
            if (length == LENGTH_MEDIUM) {
                // Switch to strong passwords.
                charset = CHARS_STRONG.toCharArray();
                length = LENGTH_STRONG;
                indices = new int[length]; // Reset indices for the new length.
            } else { // We were already generating strong passwords. No more passwords left.
                hasNext = false; // No more passwords to generate.
            }
        }
        return currentPassword; // Return the generated password.
    }

}