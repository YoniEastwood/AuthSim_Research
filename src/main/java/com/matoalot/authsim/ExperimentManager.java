package com.matoalot.authsim;

import com.matoalot.authsim.Logger.CsvLogger;
import com.matoalot.authsim.attacker.Attacker;
import com.matoalot.authsim.model.SecurityConfig;
import com.matoalot.authsim.server.Server;
import com.matoalot.authsim.utils.ConfigLoader;
import com.matoalot.authsim.utils.PasswordGenerator;


import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ExperimentManager {
    private static final int ACCOUNTS_WITH_EASY_PASSWORD = 10; // Number of easy accounts in each experiment.
    private static final int ACCOUNTS_WITH_MEDIUM_PASSWORD = 10; // Number of medium accounts in each experiment.
    private static final int ACCOUNTS_WITH_HARD_PASSWORD = 10; // Number of hard accounts in each experiment.

    public static final int GROUP_SEED = 0;


    public static void main(String[] args) {
        runExperiments();
    }



    private static void runExperiments() {
        Random random = new Random(GROUP_SEED); // Seeded random for reproducibility.
        List<String> allUsernames = new ArrayList<>();

        System.out.println("---Starting Experiment Manager---\n");


        System.out.println("Loading configurations...");
        // Load configurations from config.json
        List<SecurityConfig> experiments = ConfigLoader.loadConfigs("config.json");
        System.out.println("Configurations loaded successfully.\n");

        // Print loaded configurations for debugging.
        System.out.println("Loaded " + experiments.size() + " configurations:\n");
        for (SecurityConfig config : experiments) {
            System.out.println(config);
        }
        System.out.println();

        // Run experiments.
        System.out.println("Running experiments...\n");
        for (SecurityConfig config: experiments) {
            // Set up server for this experiment.
            Server experimentServer = setupServer(config);
            addUsersToServer(experimentServer, config, random, allUsernames);


            System.out.println("Starting experiment #" + config.experimentId + ": " + config.description);

            // Create attacker.
            Attacker attacker = new Attacker(
                    experimentServer,
                    allUsernames,
                    config.timeLimitMinutes,
                    config.maxAttempts
            );

            // Start the attack simulation.
            System.out.println("Launching attack for experiment #" + config.experimentId + "...");
            attacker.launchAttack();
            System.out.println("Attack finished for experiment #" + config.experimentId + ".");

            System.out.println("Finished experiment " + config.experimentId + "\n");
        }

    }


    // Helper method to set up server based on configuration.
    private static Server setupServer(SecurityConfig config) {
        // Create logger.
        CsvLogger logger = new CsvLogger("experiment_" + config.experimentId + "_log.csv");

        return new Server(
                config.hashAlgorithm,
                config.isPepperEnabled,
                config.attemptsUntilCAPTCHA,
                config.accountLockThreshold,
                config.lockTimeMinutes,
                config.captchaLatencyMS,
                logger
        );
    }


    // Helper method to add users to the server.
    private static void addUsersToServer(Server server, SecurityConfig config, Random random, List<String> allUsernames) {
        System.out.println("---Adding users to server for experiment #" + config.experimentId + "...");
        // Register accounts with different password strengths.
        for(int i = 1; i <= ACCOUNTS_WITH_EASY_PASSWORD; i++) {
            String username = "easyUser_" + i;
            String password = PasswordGenerator.getEasyPassword(random);

            // Register user.
            server.register(username, password);
            allUsernames.add(username);
            if (config.isTOTPEnabled) {
                server.enableTOTPForUser(username, password);
            }
        }
        for(int i = 1; i <= ACCOUNTS_WITH_MEDIUM_PASSWORD; i++) {
            String username = "mediumUser_" + i;
            String password = PasswordGenerator.getMediumPassword(random);

            // Register user.
            server.register(username, password);
            allUsernames.add(username);
            if (config.isTOTPEnabled) {
                server.enableTOTPForUser(username, password);
            }
        }
        for(int i = 1; i <= ACCOUNTS_WITH_HARD_PASSWORD; i++) {
            String username = "hardUser_" + i;
            String password = PasswordGenerator.getHardPassword(random);

            // Register user.
            server.register(username, password);
            allUsernames.add(username);
            if (config.isTOTPEnabled) {
                server.enableTOTPForUser(username, password);
            }
        }

        System.out.println("Added " + (ACCOUNTS_WITH_EASY_PASSWORD + ACCOUNTS_WITH_MEDIUM_PASSWORD + ACCOUNTS_WITH_HARD_PASSWORD) + " users to server.\n");
    }



}