import os
import pandas as pd
import numpy as np
import re
import requests
from urllib.parse import urlparse
from ruamel.yaml import YAML
import concurrent.futures
from threading import Lock
import time
from datetime import datetime
from collections import OrderedDict
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_result
import argparse
import sys

# Constants and Configuration
ASV_KEY = "asv"
BA_KEY = "ba"
GITHUB_URL_COLUMN = "Repository"
BOGIFILE_NAME = "Bogiefile"
OUTPUT_FILE = "asv_results.csv"
api_base_url = "https://github.cloud.capitalone.com/api/v3"

# Check for GitHub token
if not os.environ.get("GITHUB_TOKEN"):
    print("\033[91m\033[1m❌ FATAL ERROR: GITHUB_TOKEN environment variable required.\033[0m")
    sys.exit(1)

headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"token {os.environ.get('GITHUB_TOKEN')}",
}

# Threading locks
write_lock = Lock()
rate_limit_lock = Lock()
processed_rows_lock = Lock()

# Language and framework mappings
LANGUAGE_MAPPING = {
    'npm': 'node',
    'yarn': 'node',
    'maven': 'java',
    'gradle': 'java',
    'mvn': 'java',
    'pipenv': 'python',
    'pytest': 'python',
    'script': 'python',
    'golang': 'go',
    'docker': None
}

FRAMEWORKS_BY_LANGUAGE = {
    'java': {
        'monitoring': ['newrelic', 'micrometer', 'prometheus'],
        'logging': ['log4j', 'logback']
    },
    'node': {
        'monitoring': ['newrelic', 'prom-client'],
        'logging': ['winston', 'bunyan']
    },
    'python': {
        'monitoring': ['newrelic', 'prometheus_client', 'aws_lambda_powertools'],
        'logging': ['logging', 'structlog']
    },
    'go': {
        'monitoring': ['newrelic'],
        'logging': ['zap', 'logrus']
    }
}

# Allowed flavor values
ALLOWED_FLAVORS = {
    'container/fargate-api',
    'composite-application',
    'docker',
    'serverless-function/api',
    'devnav/docker',
    'serverless-function/composite',
    'container/fargate-consumer',
    'devnav/gear-deploy',
    'container/kubernetes',
    'serverless-function/orchestration'
}

# Rate limit tracking
rate_limit_remaining = 5000
rate_limit_reset_time = None
rate_limit_last_checked = 0

def extract_repo_info(github_url):
    """Extract owner and repo name from GitHub URL"""
    parsed_url = urlparse(github_url)
    path_parts = parsed_url.path.strip("/").split("/")
    if len(path_parts) < 2:
        raise ValueError("Invalid GitHub URL format. Expected format: https://github.com/owner/repo")
    return path_parts[0], path_parts[1]

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def download_file(owner, repo, file_path):
    """Download a file from GitHub with retries"""
    try:
        check_rate_limit()
        url = f"{api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return None
            
        content_data = response.json()
        if "content" in content_data:
            import base64
            return base64.b64decode(content_data["content"]).decode("utf-8")
        return None
    except Exception as e:
        print(f"Error downloading file {file_path}: {e}")
        return None

def check_rate_limit(response=None):
    """Check and handle GitHub rate limits"""
    global rate_limit_remaining, rate_limit_reset_time, rate_limit_last_checked
    
    current_time = time.time()
    if current_time - rate_limit_last_checked < 10 and response is None:
        return

    rate_limit_last_checked = current_time

    with rate_limit_lock:
        if response is not None:
            rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', rate_limit_remaining))
            reset_timestamp = response.headers.get('X-RateLimit-Reset')
            if reset_timestamp:
                rate_limit_reset_time = int(reset_timestamp)

        if rate_limit_remaining < 10:
            if rate_limit_reset_time:
                wait_time = max(0, rate_limit_reset_time - time.time()) + 5
                if wait_time > 0:
                    print(f"⚠️ Rate limit exceeded. Waiting {wait_time:.1f} seconds...")
                    time.sleep(wait_time)
                    rate_limit_remaining = 5000
            else:
                print("Rate limit low. Pausing for 60 seconds.")
                time.sleep(60)

def detect_language(owner, repo, initial_language):
    """Detect the actual language of a repository"""
    if initial_language and initial_language.lower() != 'docker':
        return LANGUAGE_MAPPING.get(initial_language.lower(), initial_language.lower())
    
    # Check for language-specific files
    language_files = {
        'java': ['pom.xml', 'build.gradle'],
        'node': ['package.json'],
        'python': ['requirements.txt', 'setup.py'],
        'go': ['go.mod']
    }
    
    for lang, files in language_files.items():
        for file in files:
            if check_file_exists(owner, repo, file):
                return lang
                
    return initial_language.lower() if initial_language else 'unknown'

def check_file_exists(owner, repo, file_path):
    """Check if a file exists in the repository"""
    try:
        check_rate_limit()
        url = f"{api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
        response = requests.get(url, headers=headers)
        return response.status_code == 200
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")
        return False

def analyze_frameworks(owner, repo, language):
    """Search for frameworks in the repository"""
    results = {
        'has_newrelic': False,
        'has_micrometer': False,
        'has_prometheus': False,
        'has_aws_lambda_powertools': False,
        'logging_frameworks': [],
        'monitoring_frameworks': []
    }
    
    if language not in FRAMEWORKS_BY_LANGUAGE:
        return results
    
    for framework in FRAMEWORKS_BY_LANGUAGE[language].get('monitoring', []):
        if search_in_repo(owner, repo, framework):
            if framework == 'newrelic':
                results['has_newrelic'] = True
                results['monitoring_frameworks'].append('newrelic')
            elif framework == 'micrometer':
                results['has_micrometer'] = True
                results['monitoring_frameworks'].append('micrometer')
            elif framework in ['prometheus', 'prometheus_client']:
                results['has_prometheus'] = True
                results['monitoring_frameworks'].append('prometheus')
            elif framework == 'aws_lambda_powertools':
                results['has_aws_lambda_powertools'] = True
                results['monitoring_frameworks'].append('aws_lambda_powertools')
    
    for framework in FRAMEWORKS_BY_LANGUAGE[language].get('logging', []):
        if search_in_repo(owner, repo, framework):
            results['logging_frameworks'].append(framework)
    
    return results

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def search_in_repo(owner, repo, pattern):
    """Search for a pattern in the repository"""
    try:
        check_rate_limit()
        url = f"{api_base_url}/search/code?q={pattern}+repo:{owner}/{repo}"
        response = requests.get(url, headers=headers)
        return response.status_code == 200 and response.json().get('total_count', 0) > 0
    except Exception as e:
        print(f"Error searching for {pattern}: {e}")
        return False

def process_row(row):
    """Process a single repository row with fixes for language and frameworks"""
    try:
        github_url = row['Repository']
        if not github_url.startswith(("https://", "http://")):
            github_url = f"https://{github_url}"
            
        github_url = github_url.rstrip('/')
        
        result = {
            "Repository": github_url,
            "Language": "unknown",
            "ASV": None,
            "OTEL_YES": False,
            "NR_YES": False,
            "NO_APM": True,
            "flavor": None,
            "MANUAL_CASE": False,
            "has_newrelic": False,
            "has_micrometer": False,
            "has_prometheus": False,
            "has_aws_lambda_powertools": False,
            "logging_frameworks": "",
            "monitoring_frameworks": ""
        }

        try:
            owner, repo = extract_repo_info(github_url)
            if not is_valid_repository(owner, repo):
                return result

            bogiefile_content = download_file(owner, repo, "Bogiefile")
            if not bogiefile_content:
                return result

            # Extract ASV
            asv_value = extract_asv(bogiefile_content)
            if asv_value:
                result["ASV"] = asv_value

            # Extract language and flavor
            language, flavor = extract_language_and_flavor(bogiefile_content)
            result["Language"] = language or "unknown"  # Ensure never empty
            result["flavor"] = flavor

            # Detect actual language (handles docker case)
            detected_language = detect_language(owner, repo, language)
            result["Language"] = detected_language or "unknown"  # Final fallback

            # Check for monitoring frameworks in Bogiefile
            if "OTEL_" in bogiefile_content:
                result["OTEL_YES"] = True
                result["NO_APM"] = False
            if re.search(r"NEWRLIC|NEW_RELIC", bogiefile_content, re.IGNORECASE):
                result["NR_YES"] = True
                result["NO_APM"] = False

            # Analyze frameworks if we have a valid language
            if detected_language and detected_language != 'unknown':
                framework_results = analyze_frameworks(owner, repo, detected_language)
                
                # Convert lists to comma-separated strings
                result["logging_frameworks"] = ",".join(framework_results["logging_frameworks"]) or ""
                result["monitoring_frameworks"] = ",".join(framework_results["monitoring_frameworks"]) or ""
                
                # Update boolean flags
                result.update({
                    "has_newrelic": framework_results["has_newrelic"],
                    "has_micrometer": framework_results["has_micrometer"],
                    "has_prometheus": framework_results["has_prometheus"],
                    "has_aws_lambda_powertools": framework_results["has_aws_lambda_powertools"]
                })

                # Set MANUAL_CASE based on findings
                if (result["has_newrelic"] or result["has_micrometer"] or 
                    result["has_prometheus"] or result["has_aws_lambda_powertools"] or
                    detected_language == 'go'):
                    result["MANUAL_CASE"] = True

                # Update NR_YES if New Relic found
                if result["has_newrelic"]:
                    result["NR_YES"] = True
                    result["NO_APM"] = False

                # Update NO_APM if any monitoring framework found
                if (result["OTEL_YES"] or result["NR_YES"] or 
                    result["has_micrometer"] or result["has_prometheus"] or
                    result["has_aws_lambda_powertools"]):
                    result["NO_APM"] = False

        except Exception as e:
            print(f"Error processing {github_url}: {e}")

        return result

    except Exception as e:
        print(f"Unexpected error in process_row: {e}")
        return {
            "Repository": row.get("Repository", "Unknown"),
            "Language": "unknown",
            "ASV": None,
            "OTEL_YES": False,
            "NR_YES": False,
            "NO_APM": True,
            "flavor": None,
            "MANUAL_CASE": False,
            "has_newrelic": False,
            "has_micrometer": False,
            "has_prometheus": False,
            "has_aws_lambda_powertools": False,
            "logging_frameworks": "",
            "monitoring_frameworks": ""
        }

def extract_asv(content):
    """Extract ASV from content using YAML or regex"""
    try:
        yaml = YAML(typ='safe')
        data = yaml.load(content)
        if data:
            # Check in various locations
            for key_path in [['bogie', 'asv'], ['vars', 'asv'], ['asv']]:
                value = data
                for key in key_path:
                    if isinstance(value, dict) and key in value:
                        value = value[key]
                    else:
                        value = None
                        break
                if value:
                    return str(value)
                    
        # Fallback to regex
        match = re.search(r"asv:\s*([^\s]+)", content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    except Exception as e:
        print(f"Error extracting ASV: {e}")
    return None

def extract_language_and_flavor(content):
    """Extract language and flavor from Bogiefile with flavor validation"""
    language = None
    flavor = None
    
    try:
        yaml = YAML(typ='safe')
        data = yaml.load(content)
        if data:
            # Get language from framework or tool
            if 'pipeline' in data and 'tasks' in data['pipeline']:
                build_task = data['pipeline']['tasks'].get('build', {})
                if isinstance(build_task, dict):
                    # First try framework
                    framework = build_task.get('framework')
                    if framework:
                        language = LANGUAGE_MAPPING.get(framework.lower(), framework)
                    else:
                        # Fall back to tool
                        tool = build_task.get('tool')
                        if tool:
                            language = LANGUAGE_MAPPING.get(tool.lower(), tool)
            
            # Get and validate flavor
            if 'pipeline' in data:
                pipeline = data['pipeline']
                if isinstance(pipeline, dict):
                    # Get flavor from YAML
                    flavor_candidate = pipeline.get('flavor')
                    if flavor_candidate and flavor_candidate in ALLOWED_FLAVORS:
                        flavor = flavor_candidate
                    elif flavor_candidate:
                        print(f"Warning: Invalid flavor '{flavor_candidate}' found, must be one of: {ALLOWED_FLAVORS}")
                
        # Fallback to regex if YAML parsing fails or values not found
        if not language:
            framework_match = re.search(r"framework:\s*([^\s]+)", content, re.IGNORECASE)
            if framework_match:
                framework = framework_match.group(1).strip()
                language = LANGUAGE_MAPPING.get(framework.lower(), framework)
            else:
                tool_match = re.search(r"tool:\s*([^\s]+)", content, re.IGNORECASE)
                if tool_match:
                    tool = tool_match.group(1).strip()
                    language = LANGUAGE_MAPPING.get(tool.lower(), tool)
                
        if not flavor:
            flavor_match = re.search(r"flavor:\s*([^\s]+)", content, re.IGNORECASE)
            if flavor_match:
                flavor_candidate = flavor_match.group(1).strip()
                if flavor_candidate in ALLOWED_FLAVORS:
                    flavor = flavor_candidate
                else:
                    print(f"Warning: Invalid flavor '{flavor_candidate}' found via regex")
                
    except Exception as e:
        print(f"Error extracting language/flavor: {e}")
        
    return language, flavor

def is_valid_repository(owner, repo):
    """Check if repository exists and is accessible"""
    try:
        check_rate_limit()
        url = f"{api_base_url}/repos/{owner}/{repo}"
        response = requests.get(url, headers=headers)
        return response.status_code == 200
    except Exception as e:
        print(f"Error checking repository {owner}/{repo}: {e}")
        return False

def process_chunk(chunk_tuple):
    """Process a chunk of rows from the DataFrame"""
    index, chunk = chunk_tuple
    results = []
    
    for _, row in chunk.iterrows():
        results.append(process_row(row))
    
    return (index, pd.DataFrame(results))

def process_csv_and_extract_asv_parallel(csv_file, max_workers=20):
    """Process CSV file to extract ASV information in parallel"""
    print(f"Reading CSV from {csv_file}")
    try:
        df = pd.read_csv(csv_file, names=["Repository"], header=None)
        if "Repository" not in df.columns:
            print(f"Error: Required column 'Repository' not found in {csv_file}")
            return pd.DataFrame()

        # Initialize all columns we might need
        columns = [
            "Repository", "Language", "ASV", "OTEL_YES", "NR_YES", "NO_APM",
            "flavor", "MANUAL_CASE", "has_newrelic", "has_micrometer",
            "has_prometheus", "has_aws_lambda_powertools",
            "logging_frameworks", "monitoring_frameworks"
        ]
        
        for col in columns:
            if col not in df.columns:
                df[col] = None

        # Create chunks
        chunk_size = max(1, min(50, len(df) // max_workers))
        chunks = np.array_split(df, (len(df) + chunk_size - 1) // chunk_size)
        indexed_chunks = [(i, chunk) for i, chunk in enumerate(chunks)]

        # Process in parallel
        processed_chunks = OrderedDict()
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(process_chunk, item): item[0] for item in indexed_chunks
            }

            for future in concurrent.futures.as_completed(future_to_index):
                idx, result_chunk = future.result()
                processed_chunks[idx] = result_chunk
                print(f"Completed chunk {idx} with {len(result_chunk)} rows")

        # Combine results
        results = pd.concat(processed_chunks.values(), ignore_index=True)
        print(f"Processed {len(results)} repositories in {time.time() - start_time:.2f} seconds")
        return results

    except Exception as e:
        print(f"Error in process_csv_and_extract_asv_parallel: {e}")
        return pd.DataFrame()

def write_data(data):
    """Save the processed data to output file"""
    try:
        if data.empty:
            print("⚠️ Warning: No data to write to output file")
            return

        output_path = os.path.abspath(OUTPUT_FILE)
        print(f"Writing results to {output_path}")

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Write to CSV
        data.to_csv(output_path, index=False)
        print("✓ Successfully wrote data")

    except Exception as e:
        print(f"❌ Error writing data: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract ASV information from GitHub repositories")
    parser.add_argument("-i", "--input", default="Repo_url.csv", help="Input CSV file")
    parser.add_argument("-m", "--max-workers", type=int, default=15, help="Max worker threads")
    parser.add_argument("-o", "--output", default=OUTPUT_FILE, help="Output CSV file")
    
    args = parser.parse_args()
    
    # Update output file if specified
    if args.output != OUTPUT_FILE:
        def update_output_file():
            global OUTPUT_FILE
            OUTPUT_FILE = args.output

        update_output_file()
    
    print("Starting ASV extraction process...")
    results_df = process_csv_and_extract_asv_parallel(args.input, args.max_workers)
    
    if not results_df.empty:
        write_data(results_df)
    else:
        print("No results to write")