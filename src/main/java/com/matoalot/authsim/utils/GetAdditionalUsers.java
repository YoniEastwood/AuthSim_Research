package com.matoalot.authsim.utils;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;


public class GetAdditionalUsers {

    public ArrayList<AdditionalUser> getAdditionalUsers() {
        try (InputStream inputStream = GetAdditionalUsers.class.getClassLoader()
                .getResourceAsStream("AdditionalUsers.cvs")) {

            // If the file is not found, throw an exception.
            if (inputStream == null) {
                throw new RuntimeException("Additional Users file not found!");
            }

            // Create a reader for the InputStream.
            Reader reader = new InputStreamReader(inputStream);

            // Parse the text stream as CSV.
            CSVParser csvParser = new CSVParser(reader, CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build());

            ArrayList<AdditionalUser> additionalUsers = new ArrayList<>(); // List to hold additional users.

            for (var record: csvParser) {
                String username = record.get("username");
                String password = record.get("password");
                AdditionalUser user = new AdditionalUser(username, password);
                additionalUsers.add(user);
            }

            return additionalUsers;
        } catch (IOException | RuntimeException e) {
            System.err.println("Failed to load additional users from file: " + e.getMessage());
            e.printStackTrace();
            return new ArrayList<>(); // Return empty list on failure.
        }
    }

    public class AdditionalUser {
        private final String username;
        private final String password;

        public AdditionalUser(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }
}
