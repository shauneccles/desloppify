"""Comprehensive benchmark utility for parallel execution framework.

This is a UTILITY SCRIPT, not a test file. It compares sequential vs parallel
execution performance across all detectors that use process_files_parallel.

Usage:
    python benchmark_parallel.py
    
Output:
    - Sequential and parallel execution times for each detector
    - Speedup calculations
    - Performance analysis
    
Environment Variables:
    DESLOPPIFY_PARALLEL: Set to 'true' or 'false' to control parallelization
    
Note: This script can take several minutes to run as it scans the entire
      codebase multiple times with different configurations.
"""

import multiprocessing
import os
import time
from pathlib import Path


def benchmark_detector(name: str, detector_func, path: Path, parallel: bool):
    """Benchmark a single detector."""
    os.environ['DESLOPPIFY_PARALLEL'] = 'true' if parallel else 'false'
    
    start = time.time()
    try:
        entries, total = detector_func(path)
        duration = time.time() - start
        return {
            'name': name,
            'parallel': parallel,
            'entries': len(entries),
            'files': total,
            'duration': duration,
            'success': True,
        }
    except Exception as e:
        duration = time.time() - start
        return {
            'name': name,
            'parallel': parallel,
            'entries': 0,
            'files': 0,
            'duration': duration,
            'success': False,
            'error': str(e),
        }


def run_benchmarks():
    """Run comprehensive benchmarks."""
    print("=" * 80)
    print("PARALLEL EXECUTION FRAMEWORK - COMPREHENSIVE BENCHMARK")
    print("=" * 80)
    print()
    
    # Import detectors
    from desloppify.engine.detectors.large import detect_large_files
    from desloppify.engine.detectors.complexity import detect_complexity
    from desloppify.languages.python.detectors.smells import detect_smells
    from desloppify.languages.python.detectors.dict_keys import detect_dict_key_flow, detect_schema_drift
    from desloppify.core.discovery_api import find_py_files
    
    path = Path.cwd()
    
    # Define benchmarks
    # Note: detect_complexity requires signals parameter - using empty list for benchmark
    from desloppify.engine.detectors.base import ComplexitySignal
    test_signals = [ComplexitySignal(name="try", pattern=r"try:", weight=1)]
    
    benchmarks = [
        ("Large File Detection", lambda p: detect_large_files(p, find_py_files, threshold=100)),
        ("Complexity Detection", lambda p: detect_complexity(p, test_signals, find_py_files, threshold=30)),
        ("Python Smells", detect_smells),
        ("Dict Key Flow", detect_dict_key_flow),
        ("Schema Drift", detect_schema_drift),
    ]
    
    results = []
    
    for name, detector in benchmarks:
        print(f"Benchmarking: {name}")
        print("-" * 60)
        
        # Sequential
        print("  Running sequential mode...", end=" ", flush=True)
        seq_result = benchmark_detector(name, detector, path, parallel=False)
        print(f"{seq_result['duration']:.2f}s")
        results.append(seq_result)
        
        # Parallel
        print("  Running parallel mode...  ", end=" ", flush=True)
        par_result = benchmark_detector(name, detector, path, parallel=True)
        print(f"{par_result['duration']:.2f}s")
        results.append(par_result)
        
        # Calculate speedup
        if seq_result['success'] and par_result['success']:
            speedup = seq_result['duration'] / par_result['duration'] if par_result['duration'] > 0 else 1.0
            improvement = ((speedup - 1) * 100)
            
            print(f"  Files: {seq_result['files']}")
            print(f"  Speedup: {speedup:.2f}x ({improvement:+.0f}%)")
            
            if speedup > 1.3:
                print(f"  ✅ SIGNIFICANT SPEEDUP")
            elif speedup > 1.1:
                print(f"  ⚠️  Modest improvement")
            else:
                print(f"  ⚡ Overhead exceeds benefit (use sequential)")
        else:
            if not seq_result['success']:
                print(f"  ❌ Sequential failed: {seq_result.get('error', 'unknown')}")
            if not par_result['success']:
                print(f"  ❌ Parallel failed: {par_result.get('error', 'unknown')}")
        
        print()
    
    # Summary table
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print(f"{'Detector':<30} {'Files':>8} {'Sequential':>12} {'Parallel':>12} {'Speedup':>10}")
    print("-" * 80)
    
    for i in range(0, len(results), 2):
        seq = results[i]
        par = results[i + 1]
        
        if seq['success'] and par['success']:
            speedup = seq['duration'] / par['duration'] if par['duration'] > 0 else 1.0
            print(
                f"{seq['name']:<30} {seq['files']:>8} "
                f"{seq['duration']:>10.2f}s {par['duration']:>10.2f}s "
                f"{speedup:>9.2f}x"
            )
    
    print()
    print("=" * 80)
    print("Benchmark complete!")
    print("=" * 80)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run_benchmarks()
