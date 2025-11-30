/**
 * A cube representing a line from the attack
 */

package com.matoalot.authsim.Logger;

public class LogEntry {
    public String groupSeed;
    public String timestamp;
    public String username;
    public String hashType;
    public String guess;
    public String result;
    public String protectionFlags;
    public int userAttemptNumber;
    public int globalAttemptNumber;
    public double latencyMS;

    public LogEntry(String timestamp, String username, String hashType, String guess, String result, String protectionFlags, int userAttemptNumber,int globalAttemptNumber, int latencyMS, String groupSeed) {
        this.timestamp = timestamp;
        this.username = username;
        this.hashType = hashType;
        this.guess = guess;
        this.result = result;
        this.protectionFlags = protectionFlags;
        this.userAttemptNumber = userAttemptNumber;
        this.globalAttemptNumber = globalAttemptNumber;
        this.latencyMS = latencyMS;
        this.groupSeed = groupSeed;
    }

}
