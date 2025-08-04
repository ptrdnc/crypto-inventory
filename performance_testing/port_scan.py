import subprocess
import threading
import time
import sys

# --- Configuration ---
# The target IP address to scan.
# !!! WARNING: ONLY USE AN IP YOU OWN OR HAVE EXPLICIT PERMISSION TO SCAN !!!
TARGET_IP = "127.0.0.1"  # Default to localhost for safety

# The port chunk sizes you want to test.
# 1: One thread per port (very high thread count)
# 10, 100, 1000: One thread per block of ports
CHUNK_SIZES_TO_TEST = [200, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000]

# Total ports to scan (1-65535)
TOTAL_PORTS = 65535

# Nmap command options. -T4 is for aggressive timing.
# -n disables DNS resolution, which is faster.
# -Pn treats the host as online, skipping host discovery.
# Using -T4 is generally a good balance for speed without being overly reckless.
NMAP_OPTIONS = "-T4 -n -Pn"

# --- NEW: Concurrency Limiter ---
# A Semaphore to limit the number of concurrent nmap processes.
# This prevents the "Too many open files" error. A value of 200 is a safe start.
MAX_CONCURRENT_SCANS = 200
semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)


# --- Script ---

# A global list to store results from threads
open_ports_list = []
lock = threading.Lock()

def scan_port_range(ip, port_range):
    """
    Uses nmap to scan a specific range of ports on a target IP.
    This function is now managed by a semaphore to limit concurrency.
    Args:
        ip (str): The target IP address.
        port_range (str): The port range to scan (e.g., "80-100").
    """
    # Acquire the semaphore. If the max number of threads are already running,
    # this will block until one of them finishes.
    semaphore.acquire()
    try:
        command = f"nmap {NMAP_OPTIONS} -p {port_range} {ip}"
        # Execute the nmap command
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False # Set to False to prevent raising an error on non-zero exit codes
        )
        
        # Parse the output to find open ports
        for line in result.stdout.split('\n'):
            if "/tcp" in line and "open" in line:
                port = line.split('/')[0]
                with lock:
                    open_ports_list.append(int(port))

    except Exception as e:
        print(f"An unexpected error occurred in a thread: {e}")
    finally:
        # IMPORTANT: Release the semaphore so another waiting thread can start.
        semaphore.release()


def run_scan_with_chunk_size(ip, chunk_size):
    """
    Manages a full port scan by breaking it into chunks and using threads.
    Args:
        ip (str): The target IP address.
        chunk_size (int): The number of ports each thread will scan.
    Returns:
        float: The total time taken for the scan.
    """
    print(f"\n--- Testing with chunk size: {chunk_size} (Max {MAX_CONCURRENT_SCANS} concurrent scans) ---")
    
    threads = []
    start_time = time.time()

    # Divide the total port range into chunks and create a thread for each
    for start_port in range(1, TOTAL_PORTS + 1, chunk_size):
        end_port = min(start_port + chunk_size - 1, TOTAL_PORTS)
        port_range = f"{start_port}-{end_port}"
        
        thread = threading.Thread(target=scan_port_range, args=(ip, port_range))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    end_time = time.time()
    return end_time - start_time


if __name__ == "__main__":
    print("=" * 50)
    print(" Nmap Performance Measurement Script")
    print("=" * 50)
    print("WARNING: This script performs active network scanning.")
    print("Ensure you have explicit permission to scan the target IP.")
    print("-" * 50)

    # Allow passing IP as a command-line argument
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
        print(f"Target IP set to: {TARGET_IP}")
    else:
        print(f"No target IP provided. Defaulting to localhost: {TARGET_IP}")
    
    # Check if nmap is installed
    try:
        subprocess.run("nmap --version", shell=True, check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("\nERROR: nmap is not installed or not in your system's PATH.")
        print("Please install nmap to run this script.")
        sys.exit(1)

    results = {}
    for size in CHUNK_SIZES_TO_TEST:
        # Clear the list for each run
        open_ports_list.clear()
        
        elapsed_time = run_scan_with_chunk_size(TARGET_IP, size)
        results[size] = elapsed_time
        
        print(f"  > Total time for chunk size {size}: {elapsed_time:.2f} seconds")
        print(f"  > Open ports found: {sorted(open_ports_list)}")

    print("\n\n--- Final Performance Report ---")
    for size, duration in sorted(results.items(), key=lambda item: item[1]):
        print(f"Chunk Size: {size:<5} -> Time: {duration:.2f} seconds")

    # Find and announce the fastest
    fastest_size = min(results, key=results.get)
    print("-" * 30)
    print(f"🏆 Fastest scan was with chunk size: {fastest_size}")
    print("-" * 30)
