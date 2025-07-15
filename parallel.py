#!/usr/bin/env python3
"""
Parallel GitHub Repository Analyzer with CSV support

Processes CSV files with GitHub repository URLs in parallel (up to 20 workers)
while maintaining all the original analysis functionality.
"""

import os
import sys
import csv
import json
import re
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from multiprocessing import Pool, Manager, cpu_count
import time
import math
from functools import partial

# Keep all the original GitHubRepoAnalyzer class code here (it remains unchanged)
# [Previous GitHubRepoAnalyzer class code goes here]

def analyze_repo_wrapper(analyzer, url):
    """Wrapper function for parallel processing"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        return analyzer.analyze_repository(url)
    except Exception as e:
        return {"repository": url, "error": str(e)}

def process_chunk(analyzer, chunk, progress_counter, total_count):
    """Process a chunk of URLs and update progress"""
    results = []
    for url in chunk:
        result = analyze_repo_wrapper(analyzer, url)
        results.append(result)
        with progress_counter.get_lock():
            progress_counter.value += 1
            if progress_counter.value % 10 == 0:
                print(f"Processed {progress_counter.value}/{total_count} repos ({progress_counter.value/total_count*100:.1f}%)")
    return results

def parallel_process_csv(input_file, output_file=None, max_workers=20):
    """Process CSV in parallel with multiple workers"""
    if output_file is None:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_analyzed_parallel{ext}"
    
    # Read all URLs from the CSV first
    urls = []
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            github_url = row.get('url') or row.get('github_url') or row.get('repository_url')
            if github_url:
                urls.append((github_url, row))  # Store both URL and original row
    
    total_count = len(urls)
    print(f"Found {total_count} repositories to analyze")
    
    # Determine chunk size (aim for at least 100 chunks for good load balancing)
    chunk_size = max(10, math.ceil(total_count / (max_workers * 5)))
    
    # Prepare chunks - we'll process URLs in batches
    url_chunks = [urls[i:i + chunk_size] for i in range(0, total_count, chunk_size)]
    
    # Create analyzer instances for each worker
    analyzers = [GitHubRepoAnalyzer() for _ in range(max_workers)]
    
    # Set up progress tracking
    manager = Manager()
    progress_counter = manager.Value('i', 0)
    
    # Create partial function with analyzer and progress tracking
    process_func = partial(process_chunk_with_row, progress_counter=progress_counter, total_count=total_count)
    
    print(f"Starting parallel processing with {max_workers} workers...")
    start_time = time.time()
    
    # Process in parallel
    with Pool(max_workers) as pool:
        # Map each chunk to a worker, passing an analyzer from our pool
        chunk_results = pool.starmap(process_func, 
                                   [(analyzers[i % max_workers], chunk) 
                                    for i, chunk in enumerate(url_chunks)])
    
    # Flatten results
    all_results = []
    for chunk in chunk_results:
        all_results.extend(chunk)
    
    # Write results to CSV
    with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        if not all_results:
            print("No results to write")
            return
        
        # Get fieldnames from first result that has the original row
        sample_result = next((r for r in all_results if 'original_row' in r), None)
        if not sample_result:
            print("No valid results with original rows found")
            return
            
        fieldnames = list(sample_result['original_row'].keys()) + [
            'Primary_Language',
            'Custom_Metrics_Detected',
            'Auto_Instrumentation_Compatible',
            'Recommendation',
            'Reason',
            'Has_NewRelic',
            'Has_Micrometer',
            'Has_Prometheus',
            'Has_AWS_Lambda_Powertools',
            'Logging_Frameworks',
            'Monitoring_Frameworks',
            'Manual_Case',
            'OTEL_Enabled',
            'Flavor'
        ]
        
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in all_results:
            if 'original_row' not in result:
                continue
                
            row = result['original_row'].copy()
            analysis = result['analysis']
            
            row.update({
                'Primary_Language': analysis.get('language', ''),
                'Custom_Metrics_Detected': 'Yes' if analysis.get('custom_metrics') else 'No',
                'Auto_Instrumentation_Compatible': 'Yes' if analysis.get('auto_instrumentation') else 'No',
                'Recommendation': analysis.get('recommendation', ''),
                'Reason': analysis.get('reason', ''),
                'Has_NewRelic': 'Yes' if analysis.get('has_newrelic') else 'No',
                'Has_Micrometer': 'Yes' if analysis.get('has_micrometer') else 'No',
                'Has_Prometheus': 'Yes' if analysis.get('has_prometheus') else 'No',
                'Has_AWS_Lambda_Powertools': 'Yes' if analysis.get('has_aws_lambda_powertools') else 'No',
                'Logging_Frameworks': ', '.join(analysis.get('logging_frameworks', [])) if analysis.get('logging_frameworks') else '',
                'Monitoring_Frameworks': ', '.join(analysis.get('monitoring_frameworks', [])) if analysis.get('monitoring_frameworks') else '',
                'Manual_Case': 'Yes' if analysis.get('MANUAL_CASE') else 'No',
                'OTEL_Enabled': 'Yes' if analysis.get('OTEL_YES') else 'No',
                'Flavor': analysis.get('flavor', '')
            })
            
            writer.writerow(row)
    
    elapsed_time = time.time() - start_time
    print(f"\nAnalysis complete. Processed {total_count} repositories in {elapsed_time:.1f} seconds")
    print(f"Results saved to: {output_file}")
    print(f"Average speed: {total_count/elapsed_time:.1f} repos/sec")

def process_chunk_with_row(analyzer, chunk, progress_counter, total_count):
    """Process a chunk of (url, row) pairs and update progress"""
    results = []
    for url, original_row in chunk:
        analysis = analyze_repo_wrapper(analyzer, url)
        results.append({
            'original_row': original_row,
            'analysis': analysis
        })
        with progress_counter.get_lock():
            progress_counter.value += 1
            if progress_counter.value % 10 == 0:
                print(f"Processed {progress_counter.value}/{total_count} repos ({progress_counter.value/total_count*100:.1f}%)")
    return results

def main():
    """Updated CLI entry point with parallel processing support"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python repo_analyzer.py <github_repo_url>")
        print("  python repo_analyzer.py --csv <input_csv_file> [output_csv_file] [max_workers]")
        print("\nFor parallel processing:")
        print("  python repo_analyzer.py --parallel <input_csv_file> [output_csv_file] [max_workers=20]")
        sys.exit(1)

    if sys.argv[1] == "--parallel":
        if len(sys.argv) < 3:
            print("Error: Please provide input CSV file")
            print("Usage: python repo_analyzer.py --parallel <input_csv_file> [output_csv_file] [max_workers]")
            sys.exit(1)
        
        input_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        max_workers = int(sys.argv[4]) if len(sys.argv) > 4 else 20
        
        # Cap max_workers to prevent too many simultaneous API requests
        max_workers = min(max_workers, 20)
        print(f"Using {max_workers} parallel workers")
        
        parallel_process_csv(input_file, output_file, max_workers)
    elif sys.argv[1] == "--csv":
        # Original single-process CSV processing
        if len(sys.argv) < 3:
            print("Error: Please provide input CSV file")
            print("Usage: python repo_analyzer.py --csv <input_csv_file> [output_csv_file]")
            sys.exit(1)
        
        input_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        process_csv(input_file, output_file)
    else:
        # Single URL analysis
        github_url = sys.argv[1]
        analyzer = GitHubRepoAnalyzer()
        result = analyzer.analyze_repository(github_url)

        print("\n=== Analysis Results ===")
        print(f"Repository: {result['repository']}")
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Language: {result['language']}")
            print(f"Flavor: {result.get('flavor', 'Not specified')}")
            print(f"Manual Case: {'Yes' if result['MANUAL_CASE'] else 'No'}")
            print(f"OTEL Enabled: {'Yes' if result['OTEL_YES'] else 'No'}")
            print(f"New Relic detected: {'Yes' if result['has_newrelic'] else 'No'}")
            print(f"Micrometer detected: {'Yes' if result['has_micrometer'] else 'No'}")
            print(f"Prometheus detected: {'Yes' if result['has_prometheus'] else 'No'}")
            print(f"AWS Lambda Powertools detected: {'Yes' if result['has_aws_lambda_powertools'] else 'No'}")
            print(f"Logging frameworks: {', '.join(result['logging_frameworks']) if result['logging_frameworks'] else 'None'}")
            print(f"Monitoring frameworks: {', '.join(result['monitoring_frameworks']) if result['monitoring_frameworks'] else 'None'}")
            print(f"Recommendation: {result['recommendation']}")
            print(f"Reason: {result['reason']}")
            
            if "details" in result and result["details"]:
                print("\nDetailed Findings:")
                if "auto_instrumentation" in result["details"]:
                    ai = result["details"]["auto_instrumentation"]
                    if ai.get("frameworks"):
                        print("Supported frameworks detected:")
                        for fw in ai["frameworks"]:
                            print(f"  - {fw.get('framework', fw.get('server', 'Unknown'))}")
                
                if "custom_metrics" in result["details"]:
                    cm = result["details"]["custom_metrics"]
                    if cm.get("patterns_found"):
                        print("\nCustom metrics patterns found:")
                        for pattern in cm["patterns_found"]:
                            print(f"  - {pattern}")

if __name__ == "__main__":
    main()