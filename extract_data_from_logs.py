import pandas as pd
import glob
import os

def analyze_logs():
    # 1. Find all CSV files in the current directory
    csv_files = glob.glob('*.csv')

    if not csv_files:
        print("No CSV files found in the current directory.")
        return

    summary_data = []

    print(f"Processing {len(csv_files)} files...\n")

    for file_path in csv_files:
        try:
            # Read the CSV file
            df = pd.read_csv(file_path)

            # Ensure timestamp is in datetime format
            df['timestamp'] = pd.to_datetime(df['timestamp'])

            # --- CALCULATION ---

            # 1. Runtime in minutes
            if len(df) > 0:
                start_time = df['timestamp'].min()
                end_time = df['timestamp'].max()
                duration_seconds = (end_time - start_time).total_seconds()
                runtime_minutes = duration_seconds / 60
            else:
                duration_seconds = 0
                runtime_minutes = 0

            # 2. Total Attempts
            total_attempts = len(df)

            # 3. Successful Attempts
            successful_attempts = df['result'].astype(str).str.contains('SUCCESS', case=False, na=False).sum()

            # 4. Success Rate
            success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0

            # 5. Rate (Attempts per second)
            rate_aps = (total_attempts / duration_seconds) if duration_seconds > 0 else 0

            # 6. Latency Statistics (Response Time)
            latency_mean = df['latencyMS'].mean()
            latency_median = df['latencyMS'].median()
            latency_90 = df['latencyMS'].quantile(0.90)
            latency_95 = df['latencyMS'].quantile(0.95)

            # 7. System Resources (New)
            memory_mean = df['MemoryUsageMB'].mean()
            cpu_load_mean = df['CPULoadPercentage'].mean()

            # Collect results for this file
            summary_data.append({
                'File Name': file_path,
                'Runtime (min)': round(runtime_minutes, 2),
                'Total Attempts': total_attempts,
                'Successful': successful_attempts,
                'Success Rate (%)': round(success_rate, 2),
                'Rate (req/sec)': round(rate_aps, 2),
                'Latency Mean': round(latency_mean, 2),
                'Latency Median': round(latency_median, 2),
                'Latency 90%': round(latency_90, 2),
                'Latency 95%': round(latency_95, 2),
                'Avg Memory (MB)': round(memory_mean, 2),     # Added
                'Avg CPU Load (%)': round(cpu_load_mean, 2)   # Added
            })

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

    # --- OUTPUT ---

    if summary_data:
        results_df = pd.DataFrame(summary_data)

        # Print to console
        print(results_df.to_string(index=False))

        # Save to a new CSV file
        results_df.to_csv('analysis_summary.csv', index=False)
        print("\nResults also saved to 'analysis_summary.csv'")

if __name__ == "__main__":
    analyze_logs()