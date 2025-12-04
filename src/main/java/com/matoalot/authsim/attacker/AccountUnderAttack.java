package com.matoalot.authsim.attacker;

import java.util.Iterator;

/**
 * Class representing an account that is under attack.
 */
public class AccountUnderAttack implements Comparable<AccountUnderAttack> {
    private final String username; // Username of the account under attack.
    private long lockedUntil; // Timestamp until which the account is locked.
    private Iterator<String> passwordIterator; // Iterator over possible passwords.

    /**
     * Constructor to initialize the account under attack.
     * @param username Username of the account.
     */
    public AccountUnderAttack(String username) {
        this.username = username;
        this.lockedUntil = lockedUntil = 0;
        this.passwordIterator = new PasswordIterator();
    }

    public String getUsername() {
        return username;
    }

    public boolean isLocked() {
        return System.currentTimeMillis() < lockedUntil;
    }

    public long getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(long timestamp) {
        this.lockedUntil = timestamp;
    }

    public boolean hasMorePasswords() {
        return passwordIterator.hasNext();
    }

    public String nextPassword() {
        return passwordIterator.next();
    }


    /**
     * Compare accounts under attack based on their lock time.
     * @param o Other account under attack
     * @return Comparison result.
     */
    @Override
    public int compareTo(AccountUnderAttack o) {
        return Long.compare(this.lockedUntil, o.lockedUntil);
    }
}
