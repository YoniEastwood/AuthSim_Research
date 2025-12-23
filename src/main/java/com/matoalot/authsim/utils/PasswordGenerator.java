package com.matoalot.authsim.utils;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;


/**
 * Password Generator util.
 */
public class PasswordGenerator {


    public static final List<String> COMMON_PASSWORDS_LIST = new ArrayList<>(); // Cache for common passwords.

    static{loadCommonPasswords();} // Static block to load common passwords from file once.


    // Load common passwords from CSV file in resources.
    public static void loadCommonPasswords() {
        try (InputStream inputStream = PasswordGenerator.class.getClassLoader()
                .getResourceAsStream("1000-most-common-passwords.csv")) {

            // If the file is not found, throw an exception.
            if (inputStream == null) {
                throw new FileNotFoundException("Resource file not found!");
            }

            // Create a reader for the InputStream.
            Reader reader = new InputStreamReader(inputStream);

            // Parse the text stream as CSV.
            CSVParser csvParser = new CSVParser(reader, CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build());

            // For each record in the CSV, add the password to the list.
            for (CSVRecord record : csvParser) {
                String password = record.get("password"); // Get the password.
                COMMON_PASSWORDS_LIST.add(password); // Add to the list.
            }

        } catch (IOException e) {
            throw new RuntimeException("Failed to load common passwords from CSV file.", e);
        }
    }


    // Return a random common password.
    public static String getEasyPassword(Random random) {
        Objects.requireNonNull(random, "Random generator cannot be null");
        // Return a random common password.
        int index = random.nextInt(COMMON_PASSWORDS_LIST.size());
        return COMMON_PASSWORDS_LIST.get(index);
    }

    // Return a medium complexity password.
    public static String getMediumPassword(Random random) {
        Objects.requireNonNull(random, "Random generator cannot be null");
        // Password of length 4.
        String chars = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }

    // Return a hard complexity password.
    public static String getHardPassword(Random random) {
        Objects.requireNonNull(random, "Random generator cannot be null");

        // Password of length 4.
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }
}


