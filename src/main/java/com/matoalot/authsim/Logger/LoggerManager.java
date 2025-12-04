/**
 * Centralize all logs and save them in a list
 */
package com.matoalot.authsim.Logger;

import java.util.ArrayList;
import java.util.List;

public class LoggerManager {
    private static List<LogEntry> attemptLogs = new ArrayList<>();

    /**
     * Adding to list
     * @param log - Gets one log at runtime
     */
    public static void addLog(LogEntry log) {
        attemptLogs.add(log);
    }

    /**
     * Returns the entire list
     * @return the entire list
     */
    public static List<LogEntry> getLogs() {
        return attemptLogs;
    }
}
