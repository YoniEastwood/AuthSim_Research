/**
 * A cube representing a line from the attack
 */

package com.matoalot.authsim.Logger;

public class LogEntry {
    public String timestamp;
    public String username;
    public String hashType;
    public String guess;
    public String result;
    public String protectionsState;
    public int userAttemptNumber;
    public int globalAttemptNumber;
    public double delaySeconds;
    public LogEntry(String timestamp, String username, String hashType, String guess, String result, String protectionsState, int userAttemptNumber,int globalAttemptNumber, double delaySeconds) {
        this.timestamp = timestamp;
        this.username = username;
        this.hashType = hashType;
        this.guess = guess;
        this.result = result;
        this.protectionsState = protectionsState;
        this.userAttemptNumber = userAttemptNumber;
        this.globalAttemptNumber = globalAttemptNumber;
        this.delaySeconds = delaySeconds;
    }

}
