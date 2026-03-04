"""Process monitor utility for parallel execution debugging.

This is a UTILITY SCRIPT for monitoring worker processes during parallel execution.
It monitors Python processes to verify that parallel workers are being spawned.

Usage:
    python monitor_parallel.py
    
Output:
    Real-time monitoring of:
    - Number of active Python processes
    - Peak process count during execution
    - Process monitoring in background thread
    
Note: This is primarily useful for debugging parallel execution issues
      and validating that workers are actually being spawned on Windows.
      
      For more advanced monitoring with process details, consider using psutil:
      pip install psutil
"""

import subprocess
import time
import threading
import sys

def monitor_processes():
    """Monitor Python process count."""
    max_processes = 1
    print("\nMonitoring Python processes (press Ctrl+C to stop)...")
    print("=" * 60)
    
    try:
        while True:
            result = subprocess.run(
                ["powershell", "-Command", "(Get-Process python -ErrorAction SilentlyContinue).Count"],
                capture_output=True,
                text=True
            )
            count = int(result.stdout.strip() or "0")
            max_processes = max(max_processes, count)
            
            sys.stdout.write(f"\rPython processes: {count}  (max seen: {max_processes})  ")
            sys.stdout.flush()
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\n\nFinal: Peak of {max_processes} Python processes detected")
        print("=" * 60)
        if max_processes > 5:
            print("✅ PARALLEL EXECUTION CONFIRMED - Multiple workers spawned!")
        elif max_processes > 1:
            print("⚠️  Some parallelization detected but fewer workers than expected")
        else:
            print("❌ NO PARALLELIZATION - Only 1 process detected")

if __name__ == "__main__":
    monitor_processes()
