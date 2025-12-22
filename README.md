# AuthSim Research - Password Authentication Security Analysis

> **Course:** Introduction to Online Space Security (20940)  
> **Assignment:** 16 - Comparative Analysis of Password-Based Authentication Mechanisms

## 📌 Overview
This project is a comprehensive simulation environment designed to analyze the resilience of various password authentication mechanisms against common online attacks. The system simulates both a **Server** (implementing various defense strategies) and an **Attacker** (performing Password Spraying and Brute-Force attacks).

The goal is to measure quantitative metrics such as *time-to-breach*, *success rates*, and the impact of active defense mechanisms like **CAPTCHA**, **Account Lockout**, and **TOTP** on system security.

---

## 🚀 Features

### Server Capabilities
*   **Hashing Algorithms:** Supports `SHA-256`, `BCrypt`, and `Argon2id`.
*   **Salt & Pepper:** Implementation of per-user salt and optional global Pepper secret.
*   **Active Defenses:**
    *   **Account Lockout:** Locks account after `N` failed attempts for `T` minutes.
    *   **CAPTCHA Simulation:** Enforces artificial latency after suspicious activity to simulate human verification challenges.
    *   **TOTP (Time-based One-Time Password):** Implements RFC 6238 compliant 2FA.
    *   **Rate Limiting:** Simulated via processing delays and lockout mechanisms.

### Attacker Capabilities
*   **Password Spraying:** Iterates through a list of 1000 common passwords against all users.
*   **Brute-Force:** Exhaustive key-space search for specific accounts (optimized with priority queues based on lockout timers).
*   **Smart Evasion:** The attacker logic detects lockouts and CAPTCHA requirements, sleeping or solving (simulated delay) as needed to optimize the attack flow.

---

## 🛠️ Prerequisites

*   **Java Development Kit (JDK):** Version 21 or higher.
*   **Maven:** For dependency management and building the project.
*   **Python 3.x:** For running the log analysis script.
    *   Required Python library: `pandas`

---

## 📦 Installation & Build

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YoniEastwood/AuthSim_Research.git
    cd AuthSim_Research
    ```

2.  **Build the project using Maven:**
    ```bash
    mvn clean install
    ```

---

## ⚙️ Configuration

The simulation is driven by the `src/main/resources/config.json` file. You can define multiple experiments with different security parameters.

**Example Configuration Object:**
```json
{
  "experimentId": "1",
  "description": "Baseline: SHA-256, No Protections",
  "hashAlgorithm": "SHA-256",
  "isPepperEnabled": "false",
  "isTOTPEnabled": "false",
  "attemptsUntilCAPTCHA": "0",
  "accountLockThreshold": "0",
  "lockTimeMinutes": "0",
  "captchaLatencyMS": "0",
  "timeLimitMinutes": "30",
  "maxAttempts": "100000"
}
```

---

## ▶️ Running the Simulation

To run the experiments defined in `config.json`, execute the `ExperimentManager` class.

**Run using Maven:**
```bash
mvn exec:java -Dexec.mainClass="com.matoalot.authsim.ExperimentManager"
```

**Or run the compiled JAR (if packaged with dependencies):**
```bash
java -cp target/classes:target/dependency/* com.matoalot.authsim.ExperimentManager
```

> **Output:** The simulation will generate CSV log files for each experiment (e.g., `experiment_1_log.csv`) tracking every login attempt.

---

## 📊 Analyzing Results

A Python script is provided to parse the logs and generate statistical summaries (Success Rate, Attempts/Sec, Latency, etc.).

1.  **Install dependencies:**
    ```bash
    pip install pandas
    ```

2.  **Run the analysis script:**
    ```bash
    python extract_data_from_logs.py
    ```

> **View Results:** The script outputs a summary table to the console and saves detailed analysis to `analysis_summary.csv`.

---

## 🆔 Group Information

*   **Group Seed:** `[CALCULATED_XOR_VALUE]`  
    *(Note: This seed is calculated as the Bitwise XOR of the team members' IDs. It ensures the reproducibility of the random user generation and experiment sequence.)*

### Dataset Generation
*   **Easy Users:** 10 accounts (Top 1000 common passwords).
*   **Medium Users:** 10 accounts (4-char random lowercase).
*   **Hard Users:** 10 accounts (6-char alphanumeric).

---

## 📂 Project Structure

```text
├── src
│   ├── main
│   │   ├── java/com/matoalot/authsim
│   │   │   ├── attacker       # Attack logic (Brute-force, Spraying)
│   │   │   ├── Logger         # CSV Logging utility
│   │   │   ├── model          # Data models (Account, Configs, Enums)
│   │   │   ├── server         # Server authentication logic & defenses
│   │   │   └── utils          # Hashing, TOTP, Password generation
│   │   └── resources          
│   │       ├── config.json    # Experiment configurations
│   │       ├── 1000-most-common-passwords.csv
│   │       └── AdditionalUsers.csv
│   └── test                   # JUnit tests
├── extract_data_from_logs.py  # Python analysis script
├── pom.xml                    # Maven build configuration
└── README.md                  # Project documentation
```

---

## ⚖️ Ethical Statement

> **⚠️ IMPORTANT:**  
> This project was developed strictly for educational and research purposes as part of the "Introduction to Online Space Security" course.

*   **Controlled Environment:** All experiments were conducted on a local, isolated environment. No external servers or networks were targeted.
*   **Synthetic Data:** The user database consists entirely of synthetic data generated for this simulation. No real user data or personal identifiable information (PII) was used.
*   **Tool Usage:** The attack tools developed here are designed solely for testing the resilience of the simulated server and must not be used for malicious purposes.

---

## Authors

*   Yonaton Eastwood
*   Sarah Gabrieli
