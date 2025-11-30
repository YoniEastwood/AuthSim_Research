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

    public static final int GROUP_SEED = ***REMOVED*** ^ 99999999; // TODO: Sara, enter you ID here.


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
                    config.attemptsUntilCAPTCHA
            );

            for(int i = 1; i <= ACCOUNTS_WITH_EASY_PASSWORD; i++) {
                experimentServer.register(
                        "easyUser_" + i,
                        PasswordGenerator.getEasyPassword(random),
                        config.isTOTPEnabled
                );
            }
            for(int i = 1; i <= ACCOUNTS_WITH_MEDIUM_PASSWORD; i++) {
                experimentServer.register(
                        "mediumUser_" + i,
                        PasswordGenerator.getMediumPassword(random),
                        config.isTOTPEnabled
                );
            }
            for(int i = 1; i <= ACCOUNTS_WITH_HARD_PASSWORD; i++) {
                experimentServer.register(
                        "hardUser_" + i,
                        PasswordGenerator.getHardPassword(random),
                        config.isTOTPEnabled
                );
            }

        }

    } // End of main method.

} // End of com.matoalot.authsim.ExperimentManager class.