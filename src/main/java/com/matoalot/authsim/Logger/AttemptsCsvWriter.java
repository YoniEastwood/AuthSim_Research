/**+=
 * Saving all attacks to a file
 */
package com.matoalot.authsim.Logger;

import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class AttemptsCsvWriter {
    public  static void write (String fileName, List<LogEntry> logs) throws IOException {
        FileWriter writer = new FileWriter(fileName);
        CsvWriter.writeLine(writer,
                "GROUP_SEED", "timestamp", "username", "hashMode", "guess","result","protectionFlags","userAttemptNumber","globalAttemptNumber","latencyMS");
        for (LogEntry log : logs) {
            CsvWriter.writeLine(writer,log.groupSeed, log.timestamp, log.username, log.hashType, log.guess, log.result, log.protectionFlags, String.valueOf(log.userAttemptNumber), String.valueOf(log.globalAttemptNumber), String.valueOf(log.latencyMS));
        }
        writer.close();
    }
}
