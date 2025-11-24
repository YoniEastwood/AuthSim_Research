package com.matoalot.authsim.utils;

import com.matoalot.authsim.model.SecurityConfig;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStreamReader;
import java.io.Reader;
import java.io.InputStream;
import java.util.List;
import java.lang.reflect.Type;

/**
 * Utility class to load security configurations from a JSON file.
 */
public class ConfigLoader {

    /**
     * Loads security configurations from a JSON file located in resource folder.
     * @param fileName The name of the JSON file.
     * @return A list of SecurityConfig objects.
     */
    public static List<SecurityConfig> loadConfigs(String fileName) {

        // Get the file as an InputStream.
        InputStream inputStream = ConfigLoader.class.getClassLoader().getResourceAsStream(fileName);

        // If the file is not found, throw an exception.
        if (inputStream == null) {
            throw new IllegalArgumentException("Config file not found: " + fileName);
        }

        // Create a reader for the InputStream and parse JSON.
        try (Reader reader = new InputStreamReader(inputStream)) {
            Gson gson = new Gson();


            Type listType = new TypeToken<List<SecurityConfig>>(){}.getType();

            // Convert JSON to Java Objects
            return gson.fromJson(reader, listType);

        } catch (Exception e) {
            throw new RuntimeException("Failed to load configurations from file: " + fileName, e);
        }
    }
}