import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

RESULTS_CSV = "./decentralized_results.csv"

def main():
    try:
        df = pd.read_csv(RESULTS_CSV)
    except FileNotFoundError:
        print(f"Error: '{RESULTS_CSV}' not found. Please run 'decentralized_experiment_runner.py' first.")
        return
        
    if df.empty or 'time_to_quorum_seconds' not in df.columns:
        print("Error: The results file is empty or has an incorrect format.")
        return

    time_data = pd.to_numeric(df['time_to_quorum_seconds'], errors='coerce').dropna()

    if time_data.empty:
        print("No valid time data to plot.")
        return

    mean_time = time_data.mean()
    median_time = time_data.median()
    min_time = time_data.min()
    max_time = time_data.max()

    print("\n--- Decentralized Experiment Results ---")
    print(f"Mean Time to Quorum:   {mean_time:.4f} s")
    print(f"Median Time to Quorum: {median_time:.4f} s")
    print(f"Min Time:              {min_time:.4f} s")
    print(f"Max Time:              {max_time:.4f} s")
    
    sns.set_theme(style="whitegrid", font="Tahoma")

    # สร้างกราฟ Histogram
    plt.figure(figsize=(10, 6))
    sns.histplot(time_data, bins=10, kde=True)
    plt.title('Distribution of Time-to-Quorum (n=30)', fontsize=16)
    plt.xlabel('Time (seconds)', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)
    plt.axvline(mean_time, color='r', linestyle='--', label=f'Mean: {mean_time:.3f}s')
    plt.legend()
    plt.savefig('decentralized_histogram.png')
    print("\nSaved histogram plot to 'decentralized_histogram.png'")
    plt.close()

    # สร้างกราฟ Box Plot
    plt.figure(figsize=(8, 6))
    sns.boxplot(y=time_data)
    plt.title('Box Plot of Time-to-Quorum (n=30)', fontsize=16)
    plt.ylabel('Time (seconds)', fontsize=12)
    plt.savefig('decentralized_boxplot.png')
    print("Saved box plot to 'decentralized_boxplot.png'")
    plt.close()

if __name__ == "__main__":
    main()