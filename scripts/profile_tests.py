#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import threading
import time

def get_test_binaries():
    """Builds tests and returns compiled binary executables with crate names."""
    print("Building tests to locate binaries...")
    # Using 'cargo' to get the json compiler artifacts list
    cmd = ["cargo", "test", "--no-run", "--message-format=json"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    binaries = []
    for line in proc.stdout:
        try:
            data = json.loads(line)
            if data.get("reason") == "compiler-artifact":
                executable = data.get("executable")
                if executable:
                    target = data.get("target", {})
                    binaries.append((target.get("name"), executable))
        except Exception:
            pass
    proc.wait()
    return binaries

def monitor_pid(pid, interval, samples_list):
    """Monitors resource metrics of a process and its child threads via /proc."""
    try:
        page_size = os.sysconf('SC_PAGE_SIZE')
        clk_tck = os.sysconf('SC_CLK_TCK')
    except Exception:
        page_size = 4096
        clk_tck = 100

    stat_file = f"/proc/{pid}/stat"
    statm_file = f"/proc/{pid}/statm"
    status_file = f"/proc/{pid}/status"

    prev_utime = 0
    prev_stime = 0
    prev_time = time.time()

    while True:
        if not os.path.exists(stat_file):
            break
        try:
            # Memory usage from statm
            with open(statm_file, 'r') as f:
                parts = f.read().split()
                vmem = int(parts[0]) * page_size
                rss = int(parts[1]) * page_size
                shared = int(parts[2]) * page_size

            # Threads count from status
            threads = 1
            with open(status_file, 'r') as f:
                for line in f:
                    if line.startswith("Threads:"):
                        threads = int(line.split()[1])
                        break

            # CPU usage from stat
            with open(stat_file, 'r') as f:
                stat_parts = f.read().split()
                utime = int(stat_parts[13])
                stime = int(stat_parts[14])

            now = time.time()
            elapsed = now - prev_time
            if elapsed > 0:
                cpu_jiffies = (utime - prev_utime) + (stime - prev_stime)
                cpu_usage = (cpu_jiffies / clk_tck) / elapsed * 100
            else:
                cpu_usage = 0.0

            prev_utime = utime
            prev_stime = stime
            prev_time = now

            samples_list.append({
                "time": now,
                "rss": rss,
                "vmem": vmem,
                "shared": shared,
                "threads": threads,
                "cpu": cpu_usage
            })
        except Exception:
            # Process exited mid-read
            break
        time.sleep(interval)

def profile_test_suite(name, executable, interval=0.01):
    """Runs a single test binary, monitors it, and returns the stats."""
    print(f"Profiling suite: {name}...")
    samples = []
    
    start_time = time.time()
    # Run the test binary in a subprocess
    proc = subprocess.Popen(
        [executable],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Spawn monitoring thread
    monitor_thread = threading.Thread(
        target=monitor_pid,
        args=(proc.pid, interval, samples)
    )
    monitor_thread.start()
    
    # Wait for execution to finish
    stdout, stderr = proc.communicate()
    end_time = time.time()
    monitor_thread.join()
    
    duration = end_time - start_time
    
    return {
        "name": name,
        "duration": duration,
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "samples": samples
    }

def generate_report(results, report_md_path):
    """Generates a detailed Markdown report with performance metrics and potential leaks."""
    os.makedirs(os.path.dirname(report_md_path), exist_ok=True)
    
    md = []
    md.append("# AI-Native Kernel Test Profiler Report\n")
    md.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    md.append("## Executive Summary\n")
    
    total_duration = sum(r["duration"] for r in results)
    total_suites = len(results)
    
    # Calculate overall peaks
    overall_peak_rss = 0
    overall_max_threads = 0
    leak_warnings = []
    slow_tests = []
    
    for r in results:
        samples = r["samples"]
        if not samples:
            continue
        peak_rss = max(s["rss"] for s in samples)
        overall_peak_rss = max(overall_peak_rss, peak_rss)
        
        max_threads = max(s["threads"] for s in samples)
        overall_max_threads = max(overall_max_threads, max_threads)
        
        # Heuristics:
        # 1. Leak detection: RSS grows over time and remains high
        if len(samples) > 10:
            initial_rss = sum(s["rss"] for s in samples[:3]) / 3
            final_rss = sum(s["rss"] for s in samples[-3:]) / 3
            rss_increase = final_rss - initial_rss
            # If RSS grew by more than 1MB and final is 20% higher than initial
            if rss_increase > 1024 * 1024 and final_rss > 1.2 * initial_rss:
                leak_warnings.append((r["name"], rss_increase / (1024 * 1024)))
                
        # 2. Slow execution detection (duration > 150ms for prototype test suites)
        if r["duration"] > 0.15:
            slow_tests.append((r["name"], r["duration"]))

    md.append(f"- **Total Test Suites Profiled**: {total_suites}")
    md.append(f"- **Total Execution Time**: {total_duration:.3f} seconds")
    md.append(f"- **Peak Resident Memory (RSS)**: {overall_peak_rss / (1024 * 1024):.2f} MB")
    md.append(f"- **Max Concurrent Threads**: {overall_max_threads}")
    md.append("\n")
    
    # Alerts section
    if leak_warnings or slow_tests:
        md.append("### ⚠️ Performance Alerts\n")
        for suite, size in leak_warnings:
            md.append(f"- 🔴 **Potential Memory Leak** in `{suite}`: RSS memory grew by **{size:.2f} MB** during the run.")
        for suite, dur in slow_tests:
            md.append(f"- 🟡 **Slow Suite** `{suite}`: Took **{dur*1000:.1f} ms** to complete (threshold 150ms).")
        md.append("\n")
    else:
        md.append("✅ **All checks clean! No obvious memory leaks or performance bottlenecks detected.**\n")

    # Detailed table
    md.append("## Test Suite Resource Metrics\n")
    md.append("| Test Suite | Exit Code | Duration (s) | Peak RSS (MB) | RSS Delta (MB) | Peak Threads | Peak CPU (%) |")
    md.append("|---|---|---|---|---|---|---|")
    
    for r in results:
        samples = r["samples"]
        if not samples:
            md.append(f"| `{r['name']}` | {r['exit_code']} | {r['duration']:.3f} | N/A | N/A | N/A | N/A |")
            continue
            
        peak_rss = max(s["rss"] for s in samples) / (1024 * 1024)
        initial_rss = samples[0]["rss"] / (1024 * 1024)
        final_rss = samples[-1]["rss"] / (1024 * 1024)
        rss_delta = final_rss - initial_rss
        max_threads = max(s["threads"] for s in samples)
        peak_cpu = max(s["cpu"] for s in samples)
        
        md.append(f"| `{r['name']}` | {r['exit_code']} | {r['duration']:.3f} | {peak_rss:.2f} MB | {rss_delta:+.2f} MB | {max_threads} | {peak_cpu:.1f}% |")

    # Output stats over time for each suite
    md.append("\n## Detailed Memory & CPU Timelines\n")
    for r in results:
        samples = r["samples"]
        if not samples:
            continue
        md.append(f"### Suite `{r['name']}`")
        md.append(f"- Duration: **{r['duration']:.3f} s**")
        md.append(f"- Timeline Samples: {len(samples)}")
        md.append("\nSampled timeline values (5 intervals):")
        
        step = max(1, len(samples) // 5)
        timeline_rows = []
        for i in range(0, len(samples), step):
            s = samples[i]
            t_rel = s["time"] - samples[0]["time"]
            timeline_rows.append(f"  - `{t_rel*1000:4.1f} ms` -> CPU: **{s['cpu']:5.1f}%** | RSS: **{s['rss']/(1024*1024):5.2f} MB** | Threads: **{s['threads']}**")
        md.append("\n".join(timeline_rows))
        md.append("\n")

    with open(report_md_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(md))
        
    print(f"\nReport written to: {report_md_path}")
    
    # Print summary console output
    print("=" * 60)
    print(" PERFORMANCE SUMMARY ".center(60, "="))
    print(f"Total Suites: {total_suites} | Time: {total_duration:.3f}s | Peak RSS: {overall_peak_rss / (1024 * 1024):.2f}MB")
    if leak_warnings:
        print(f"⚠️  Found {len(leak_warnings)} potential memory leaks!")
    else:
        print("✅  No memory leaks detected.")
    print("=" * 60)

def main():
    binaries = get_test_binaries()
    if not binaries:
        print("No test binaries found. Make sure tests are defined in Cargo workspace.")
        return

    print(f"Found {len(binaries)} test suites to profile.")
    
    results = []
    for name, executable in binaries:
        res = profile_test_suite(name, executable)
        results.append(res)
        
    report_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "target", "reports", "test_profile_report.md"
    )
    generate_report(results, report_path)

if __name__ == "__main__":
    main()
