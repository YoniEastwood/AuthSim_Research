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
                "timestamp", "username", "hashtype", "guess","result","protectionState","userAttemptNumber","globalAttemptNumber","delaySeconds");
        for (LogEntry log : logs) {
            CsvWriter.writeLine(writer,log.timestamp, log.username, log.hashType, log.guess, log.result, log.protectionsState, String.valueOf(log.userAttemptNumber), String.valueOf(log.globalAttemptNumber), String.valueOf(log.delaySeconds));
        }
        writer.close();
    }
}
