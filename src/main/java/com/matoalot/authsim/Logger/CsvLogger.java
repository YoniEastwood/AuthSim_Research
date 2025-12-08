package com.matoalot.authsim.Logger;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class CsvLogger {
    private final String FILE_PATH; // Path to the CSV file.

    // Headers for the CSV file.
    private static final String[] HEADERS = {
            "GROUP_SEED", "timestamp", "username", "hashMode",
            "guess", "result", "protectionFlags",
            "userAttemptNumber", "globalAttemptNumber", "latencyMS",
            "MemoryUsageMB", "CPULoadPercentage"
    };

    /**
     * Constructor for CsvLogger.
     * @param filePath Path to the CSV file.
     */
    public CsvLogger(String filePath) {
        this.FILE_PATH = filePath;

        // Remove existing file to start fresh.
        File file = new File(filePath);
        if (file.exists()) {
            boolean deleted = file.delete();
            if (!deleted) {
                System.err.println("Warning: Could not delete old log file. New logs will be appended.");
            }
        }
    }

    /**
     * Log an entry to the CSV file.
     * @param log LogEntry object containing the log details.
     */
    public void log(LogEntry log) {
        if (log == null) {
            throw new IllegalArgumentException("LogEntry cannot be null");
        }

        File file = new File(FILE_PATH);
        boolean isNewFile = !file.exists();


        CSVFormat format = CSVFormat.DEFAULT.builder()
                .setHeader(HEADERS)
                .setSkipHeaderRecord(!isNewFile) // Write header only if file is new.
                .build();

        try (FileWriter fw = new FileWriter(file, true);
             CSVPrinter printer = new CSVPrinter(fw, format)) {

            // Write the log entry to the CSV.
            printer.printRecord(
                    log.groupSeed,
                    log.timestamp,
                    log.username,
                    log.hashType,
                    log.guess,
                    log.result,
                    log.protectionFlags,
                    log.userAttemptNumber,
                    log.globalAttemptNumber,
                    log.latencyMS,
                    log.MemoryUsageMB,
                    log.CPULoadPercentage
            );

        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
            e.printStackTrace();
        }
    }
}