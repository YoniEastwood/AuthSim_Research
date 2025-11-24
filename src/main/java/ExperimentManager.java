import com.matoalot.authsim.model.SecurityConfig;
import com.matoalot.authsim.server.Server;
import com.matoalot.authsim.utils.ConfigLoader;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ExperimentManager {
    public static final int ACCOUNTS_WITH_EASY_PASSWORD = 10; // Number of easy accounts in each experiment.
    public static final int ACCOUNTS_WITH_MEDIUM_PASSWORD = 10; // Number of medium accounts in each experiment.
    public static final int ACCOUNTS_WITH_HARD_PASSWORD = 10; // Number of hard accounts in each experiment.
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
                    config.isSaltEnabled
            );

            for(int i = 1; i <= ACCOUNTS_WITH_EASY_PASSWORD; i++) {
                experimentServer.registerAccount(
                        "easyUser_" + i,
                        PasswordGenerator.getEasyPassword(random),
                        config.isTOTPEnabled
                );
            }
            for(int i = 1; i <= ACCOUNTS_WITH_MEDIUM_PASSWORD; i++) {
                experimentServer.registerAccount(
                        "mediumUser_" + i,
                        PasswordGenerator.getMediumPassword(random),
                        config.isTOTPEnabled
                );
            }
            for(int i = 1; i <= ACCOUNTS_WITH_HARD_PASSWORD; i++) {
                experimentServer.registerAccount(
                        "hardUser_" + i,
                        PasswordGenerator.getHardPassword(random),
                        config.isTOTPEnabled
                );
            }

        }

    } // End of main method.


    // Helper class for generating passwords of varying complexity.
    private static class PasswordGenerator {
        private static final List<String> COMMON_PASSWORDS_LIST = new ArrayList<>(); // Cache for common passwords.

        static{loadCommonPasswords();} // Static block to load common passwords once.


        // Load common passwords from CSV file in resources.
        public static void loadCommonPasswords() {
            try (InputStream inputStream = ExperimentManager.class.getClassLoader()
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
            // Return a random common password.
            int index = random.nextInt(COMMON_PASSWORDS_LIST.size());
            return COMMON_PASSWORDS_LIST.get(index);
        }

        // Return a medium complexity password.
        public static String getMediumPassword(Random random) {
            // Password of length 6.
            String chars = "abcdefghijklmnopqrstuvwxyz";
            StringBuilder password = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                password.append(chars.charAt(random.nextInt(chars.length())));
            }

            return password.toString();
        }

        // Return a hard complexity password.
        public static String getHardPassword(Random random) {
            // Password of length 8.
            String chars = "abcdefghijklmnopqrstuvwxyz0123456789!";
            StringBuilder password = new StringBuilder();
            for (int i = 0; i < 12; i++) {
                password.append(chars.charAt(random.nextInt(chars.length())));
            }

            return password.toString();
        }
    }
}
