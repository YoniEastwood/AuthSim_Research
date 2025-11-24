package com.matoalot.authsim.utils;

import com.matoalot.authsim.model.SecurityConfig;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStreamReader;
import java.io.Reader;
import java.io.InputStream;
import java.util.List;
import java.lang.reflect.Type;

public class ConfigLoader {

    public static List<SecurityConfig> loadConfigs(String fileName) {
        // Use ClassLoader to find the file in src/main/resources
        InputStream inputStream = ConfigLoader.class.getClassLoader().getResourceAsStream(fileName);

        if (inputStream == null) {
            System.err.println("File not found: " + fileName);
            return null;
        }

        try (Reader reader = new InputStreamReader(inputStream)) {
            Gson gson = new Gson();

            // Define the type: List of SecurityConfig
            Type listType = new TypeToken<List<SecurityConfig>>(){}.getType();

            // Convert JSON to Java Objects
            return gson.fromJson(reader, listType);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}