import com.matoalot.authsim.model.SecurityConfig;
import com.matoalot.authsim.server.Server;
import com.matoalot.authsim.utils.ConfigLoader;

import java.util.List;

public class ExperimentManager {

    public static void main(String[] args) {
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


        for (SecurityConfig config: experiments) {
            System.out.println("Starting experiment #" + config.experimentId + ": " + config.description);

            // TODO: Initialize and start the server with the given configuration.
            Server experimentServer = new Server(

            );
        }

    }
}
