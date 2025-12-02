package com.matoalot.authsim;

import com.matoalot.authsim.model.SecurityConfig;
import com.matoalot.authsim.server.Server;
import com.matoalot.authsim.utils.ConfigLoader;
import com.matoalot.authsim.utils.PasswordGenerator;


import java.util.List;
import java.util.Random;

public class ExperimentManager {
    private static final int ACCOUNTS_WITH_EASY_PASSWORD = 10; // Number of easy accounts in each experiment.
    private static final int ACCOUNTS_WITH_MEDIUM_PASSWORD = 10; // Number of medium accounts in each experiment.
    private static final int ACCOUNTS_WITH_HARD_PASSWORD = 10; // Number of hard accounts in each experiment.

    public static final int GROUP_SEED = ***REMOVED*** ^ ***REMOVED***;



    public static void main(String[] args) {
        Random random = new Random(GROUP_SEED); // Seeded random for reproducibility.

        System.out.println("---Starting Experiment Manager---\n");

        System.out.println("Loading configurations...");
        // Load configurations from config.json
        List<SecurityConfig> experiments = ConfigLoader.loadConfigs("config.json");
        if (experiments == null || experiments.isEmpty()) {
            System.err.println("Error: No configurations loaded. Check config.json path or syntax.");
            return;
        }
        // Print loaded configurations for debugging.
        System.out.println("Loaded " + experiments.size() + " configurations:\n");
        for (SecurityConfig config : experiments) {
            System.out.println(config);
        }


        // Run experiments.
        System.out.println("Running experiments...\n");
        for (SecurityConfig config: experiments) {
            System.out.println("Starting experiment #" + config.experimentId + ": " + config.description);

            // Create server with specified configuration.
            Server experimentServer = new Server(
                    config.hashAlgorithm,
                    config.isPepperEnabled,
                    config.attemptsUntilCAPTCHA,
                    config.accountLockThreshold,
                    config.lockTimeMinutes,
                    config.totpTriesUntilSessionLock,
                    config.captchaLatencyMS
            );

            // Register accounts with different password strengths.
            for(int i = 1; i <= ACCOUNTS_WITH_EASY_PASSWORD; i++) {
                String username = "easyUser_" + i;
                String password = PasswordGenerator.getEasyPassword(random);

                // Register user.
                experimentServer.register(username, password);
                if (config.isTOTPEnabled) {
                    experimentServer.enableTOTPForUser(username, password);
                }
            }
            for(int i = 1; i <= ACCOUNTS_WITH_MEDIUM_PASSWORD; i++) {
                String username = "mediumUser_" + i;
                String password = PasswordGenerator.getMediumPassword(random);

                // Register user.
                experimentServer.register(username, password);
                if (config.isTOTPEnabled) {
                    experimentServer.enableTOTPForUser(username, password);
                }
            }
            for(int i = 1; i <= ACCOUNTS_WITH_HARD_PASSWORD; i++) {
                String username = "hardUser_" + i;
                String password = PasswordGenerator.getHardPassword(random);

                // Register user.
                experimentServer.register(username, password);
                if (config.isTOTPEnabled) {
                    experimentServer.enableTOTPForUser(username, password);
                }
            }

        }

    } // End of main method.

} // End of com.matoalot.authsim.ExperimentManager class.