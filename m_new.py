import os
import pandas as pd
import numpy as np
import re
import shutil
import stat
import requests
from urllib.parse import urlparse
from ruamel.yaml import YAML
from io import StringIO
import concurrent.futures
import csv
from threading import Lock
import re
import time
from datetime import datetime
from collections import OrderedDict
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    retry_if_result,
)
import argparse
import threading
import sys

ASV_KEY = "asv"
BA_KEY = "ba"

# Check for GitHub token - exit if not available
if not os.environ.get("GITHUB_TOKEN"):
    print(
        "\033[91m\033[1m❌ FATAL ERROR: GITHUB_TOKEN environment variable required. Run: export GITHUB_TOKEN=your_token_here\033[0m"
    )
    sys.exit(1)

# Constants
GITHUB_URL_COLUMN = "Repository"
BOGIFILE_NAME = "Bogiefile"
OUTPUT_FILE = "asv_results.csv"
write_lock = Lock()
rate_limit_lock = Lock()  # Lock for accessing shared rate limit info
processed_rows_lock = Lock()  # Lock for updating the processed rows counter
headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"token {os.environ.get('GITHUB_TOKEN')}",
}
api_base_url = "https://github.cloud.capitalone.com/api/v3"

# Pattern to match ASV but exclude YAML anchors and references
pattern = r"(?<!&)(?<!*)asv:(\s+)?([^\s&*]+)"

# Rate limit tracking globals
rate_limit_remaining = 5000  # Default GitHub rate limit
rate_limit_reset_time = None
rate_limit_last_checked = 0

# Progress tracking globals
last_progress_time = 0  # Time of last progress update

# Logging and monitoring frameworks by language
LOGGING_FRAMEWORKS = {
    'java': {
        'monitoring': ['newrelic', 'micrometer', 'prometheus'],
        'logging': ['log4j', 'logback', 'chassislogger', 'chassis springboot']
    },
    'javascript': {
        'monitoring': ['newrelic', 'prom-client'],
        'logging': ['winston', 'pino', 'bunyan', 'npmlog', 'tracer']
    },
    'python': {
        'monitoring': ['newrelic', 'prometheus_client', 'aws_lambda_powertools'],
        'logging': ['pythonjsonlogger', 'logging', 'structlog']
    },
    'go': {
        'monitoring': ['newrelic'],
        'logging': ['zap', 'log/slog', 'logrus']
    }
}

def extract_repo_info(github_url):
    """Extract owner and repo name from GitHub URL"""
    parsed_url = urlparse(github_url)
    path_parts = parsed_url.path.strip("/").split("/")

    if len(path_parts) < 2:
        raise ValueError(
            "Invalid GitHub URL format. Expected format: https://github.com/owner/repo"
        )

    return path_parts[0], path_parts[1]


def is_valid_repository(owner, repo):
    """Check if a repository exists and is accessible"""
    check_url = f"{api_base_url}/repos/{owner}/{repo}"

    try:
        response = requests.get(check_url, headers=headers)
        time.sleep(1)
        # Return True if repo exists (200 OK)
        return response.status_code == 200
    except Exception as e:
        print(f"Error checking repository {owner}/{repo}: {e}")
        return False


def is_none(value):
    """Helper function to check if a value is None for retry logic"""
    return value is None


def check_rate_limit(response=None):
    """Check GitHub rate limits and wait if we're close to hitting them"""
    global rate_limit_remaining, rate_limit_reset_time, rate_limit_last_checked

    # Only check rate limits every 10 seconds at most to avoid constant checking
    current_time = time.time()
    if current_time - rate_limit_last_checked < 10 and response is None:
        return

    rate_limit_last_checked = current_time

    with rate_limit_lock:
        # If we have a response, extract rate limit info from it
        if response is not None:
            rate_limit_remaining = int(
                response.headers.get("X-RateLimit-Remaining", rate_limit_remaining)
            )
            reset_timestamp = response.headers.get("X-RateLimit-Reset")
            if reset_timestamp:
                rate_limit_reset_time = int(reset_timestamp)

        # If we're running low on remaining calls, wait until reset
        if rate_limit_remaining < 10:
            if rate_limit_reset_time:
                wait_time = (
                    max(0, rate_limit_reset_time - time.time()) + 5
                )  # Add 5 seconds buffer
                if wait_time > 0:
                    print(
                        f"⚠️⚠️⚠️ RATE LIMIT EXCEEDED! Reset at: {datetime.fromtimestamp(rate_limit_reset_time)}, waiting {wait_time:.1f} sec ⚠️⚠️⚠️"
                    )
                    time.sleep(wait_time)
                    # After waiting, assume our limit has been reset
                    rate_limit_remaining = 5000
            else:
                # If we don't know reset time, use a conservative approach and pause briefly
                print(
                    f" Rate limit low ({rate_limit_remaining} remaining) but reset time unknown. Pausing for 60 seconds."
                )
                time.sleep(60)


def should_retry(result):
    """Custom retry predicate that checks both the result and any stored status code"""
    # Don't retry on 404s (file not found)
    if (
        hasattr(should_retry, "last_status_code")
        and should_retry.last_status_code == 404
    ):
        return False
    return result is None


@retry(
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_exponential(
        multiplier=1, min=4, max=10
    ),  # Wait 4-10 seconds between retries
    retry=retry_if_result(should_retry),  # Use custom retry predicate
)
def download_file(owner, repo, file_path):
    """Download a specific file from the repository with exponential backoff retries using tenacity"""
    try:
        api_url = f"{api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
        print(f"Downloading {file_path} from {api_url}")

        # Make the request with a timeout
        response = requests.get(api_url, headers=headers, timeout=10)
        print(f"Response status code: {response.status_code} {api_url}")

        # Store the status code for the retry predicate
        should_retry.last_status_code = response.status_code

        # Check for rate limit errors specifically
        if (
            response.status_code == 403
            and "rate limit exceeded" in response.text.lower()
        ):
            print(
                f"🛑 RATE LIMIT ERROR: Failed to download {owner}/{repo}/{file_path} - processing incomplete until limit reset 🛑"
            )
            return None

        time.sleep(1)

        if response.status_code != 200:
            # File not found or error accessing it
            return None

        try:
            content_data = response.json()
            if "content" in content_data:
                import base64

                content = base64.b64decode(content_data["content"]).decode("utf-8")
                return content
        except ValueError as ve:
            print(f"Error decoding JSON response: {ve}")
            return None
        except Exception as e:
            print(f"Error processing content: {e}")
            return None

        return None
    except requests.Timeout:
        print(f"Timeout downloading file {file_path} from {api_url}")
        return None
    except Exception as e:
        print(f"Error downloading file {file_path} from {api_url}: {e}")
        return None


def read_yaml(content):
    """Read YAML content safely, allowing duplicate keys"""
    try:
        yaml = YAML(typ="safe")
        # Configure to use the last seen value for duplicate keys
        yaml.allow_duplicate_keys = True
        return yaml.load(content)
    except Exception as e:
        # If YAML parsing fails, try regex directly on the content
        content_str = content.strip()
        result = {}

        # Look for ASV with or without anchor (&)
        asv_match = re.search(
            r"^\sasv\s:(?:\s*&[^\s]+)?\s*([^\n\r,}]]+)",
            content_str,
            re.MULTILINE | re.IGNORECASE,
        )
        if asv_match:
            result["asv"] = asv_match.group(1).strip()
            return result

        # Look for BA with or without anchor (&)
        ba_match = re.search(
            r"^\sba\s:(?:\s*&[^\s]+)?\s*([^\n\r,}]]+)",
            content_str,
            re.MULTILINE | re.IGNORECASE,
        )
        if ba_match:
            result["ba"] = ba_match.group(1).strip()
            return result

        return None


def find_asv_recursively(yaml_data):
    """Find ASV or BA value in YAML data"""
    if not isinstance(yaml_data, dict):
        return None

    # Look in top-level vars if present
    vars_data = yaml_data.get("vars", {})
    bogie_data = yaml_data.get("bogie", {})

    # For v1
    if isinstance(bogie_data, dict):
        # First check for ASV
        asv_value = bogie_data.get(ASV_KEY)
        if asv_value:
            return str(asv_value)

        # If no ASV, check for BA
        ba_value = bogie_data.get(BA_KEY)
        if ba_value:
            return str(ba_value)

    # For v2
    if isinstance(vars_data, dict):
        # First check for ASV
        asv_value = vars_data.get(ASV_KEY)
        if asv_value:
            return str(asv_value)

        # If no ASV, check for BA
        ba_value = vars_data.get(BA_KEY)
        if ba_value:
            return str(ba_value)

    # If not found in vars, check top level
    asv_value = yaml_data.get(ASV_KEY)
    if asv_value:
        return str(asv_value)

    ba_value = yaml_data.get(BA_KEY)
    if ba_value:
        return str(ba_value)

    return None


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_result(is_none),
)
def search_code_for_patterns(owner, repo, language):
    """Search repository code for monitoring and logging framework patterns"""
    results = {
        'has_newrelic': False,
        'has_micrometer': False,
        'has_prometheus': False,
        'has_aws_lambda_powertools': False,
        'has_goblet': False,
        'logging_frameworks': [],
        'monitoring_frameworks': []
    }
    
    if language.lower() not in LOGGING_FRAMEWORKS:
        return results
    
    frameworks = LOGGING_FRAMEWORKS[language.lower()]
    
    try:
        # Search for monitoring frameworks
        for framework in frameworks.get('monitoring', []):
            query = f"{framework} repo:{owner}/{repo}"
            url = f"{api_base_url}/search/code?q={query}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200 and response.json().get('total_count', 0) > 0:
                if framework == 'newrelic':
                    results['has_newrelic'] = True
                    results['monitoring_frameworks'].append('newrelic')
                elif framework == 'micrometer':
                    results['has_micrometer'] = True
                    results['monitoring_frameworks'].append('micrometer')
                elif framework == 'prometheus' or framework == 'prometheus_client':
                    results['has_prometheus'] = True
                    results['monitoring_frameworks'].append('prometheus')
                elif framework == 'aws_lambda_powertools':
                    results['has_aws_lambda_powertools'] = True
                    results['monitoring_frameworks'].append('aws_lambda_powertools')
        
        # Search for logging frameworks
        for framework in frameworks.get('logging', []):
            query = f"{framework} repo:{owner}/{repo}"
            url = f"{api_base_url}/search/code?q={query}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200 and response.json().get('total_count', 0) > 0:
                results['logging_frameworks'].append(framework)
        
        return results
    
    except Exception as e:
        print(f"Error searching code in {owner}/{repo}: {e}")
        return results


def process_row(row):
    """Process a single row to extract ASV info - used for more granular parallelization"""
    try:
        github_url = f"https://{row['Repository']}"
        result = {
            "Repository": row["Repository"],
            "Language": None,
            "Deployment": None,
            "SearchText": None,
            "ASV": "INVALID_REPO",
            "OTEL_YES": False,
            "NR_YES": False,
            "NO_APM": False,
            "Language": None,
            "flavor": None,
            "MANUAL_CASE": False,
            "has_newrelic": False,
            "has_micrometer": False,
            "has_prometheus": False,
            "has_aws_lambda_powertools": False,
            "has_goblet": False,
            "logging_frameworks": None,
            "monitoring_frameworks": None
        }

        try:
            owner, repo = extract_repo_info(github_url)

            if not is_valid_repository(owner, repo):
                print(f"Repository does not exist or is inaccessible: {github_url}")
                return result

            bogiefile_content = download_file(owner, repo, "Bogiefile")

            if bogiefile_content is not None:
                result["ASV"] = "None"
                result["OTEL_YES"] = False
                result["NR_YES"] = False
                result["NO_APM"] = True
                result["Language"] = None
                result["flavor"] = None

                asv_value = None

                try:
                    bogie_yaml = read_yaml(bogiefile_content)
                    if bogie_yaml and isinstance(bogie_yaml, dict):
                        if "bogie" in bogie_yaml and isinstance(bogie_yaml["bogie"], dict):
                            bogie_data = bogie_yaml["bogie"]
                            if "asv" in bogie_data:
                                asv_value = bogie_data["asv"]
                        elif "vars" in bogie_yaml and isinstance(bogie_yaml["vars"], dict):
                            vars_data = bogie_yaml["vars"]
                            if "asv" in vars_data:
                                asv_value = vars_data["asv"]

                        if "pipeline" in bogie_yaml:
                            pipeline = bogie_yaml["pipeline"]
                            if isinstance(pipeline, dict):
                                result["flavor"] = pipeline.get("flavor")
                                if "tasks" in pipeline and "build" in pipeline["tasks"]:
                                    result["Language"] = pipeline["tasks"]["build"].get("tool")
                except Exception as yaml_e:
                    print(f"Error parsing YAML for {github_url}: {yaml_e}")

                if asv_value is None:
                    try:
                        asv_match = re.search(pattern, bogiefile_content, re.IGNORECASE)
                        if asv_match:
                            asv_value = asv_match.group(2).strip()
                            print(f"Found ASV via regex: {asv_value}")
                    except Exception as regex_e:
                        print(f"Error in regex ASV extraction: {regex_e}")

                if asv_value is not None:
                    result["ASV"] = asv_value

                if result["flavor"] is None or result["Language"] is None:
                    try:
                        if result["flavor"] is None and "flavor:" in bogiefile_content:
                            flavor_match = re.search(r"flavor:\s*([\w/-]+)", bogiefile_content)
                            if flavor_match:
                                result["flavor"] = flavor_match.group(1).strip()

                        if result["Language"] is None and "tool:" in bogiefile_content:
                            tool_match = re.search(r"tool:\s*([\w/-]+)", bogiefile_content)
                            if tool_match:
                                result["Language"] = tool_match.group(1).strip()
                    except Exception as regex_e:
                        print(f"Error in fallback string search for {github_url}: {regex_e}")

                # Check for OTEL_ in Bogiefile
                if "OTEL_" in bogiefile_content:
                    result["OTEL_YES"] = True
                    result["NO_APM"] = False

                # Check for NEWRLIC or NEW_RELIC (case insensitive)
                if re.search(r"NEWRLIC|NEW_RELIC", bogiefile_content, re.IGNORECASE):
                    result["NR_YES"] = True
                    result["NO_APM"] = False

                if not result["OTEL_YES"] and not result["NR_YES"]:
                    result["NO_APM"] = True

                # Perform code search based on language
                if result["Language"]:
                    # Convert npm to node for consistency
                    if result["Language"].lower() in ["npm", "yarn"]:
                        result["Language"] = "node"
                    # Convert maven to java for consistency
                    elif result["Language"].lower() in ["maven", "gradle", "mvn"]:
                        result["Language"] = "java"
                    elif result["Language"].lower() in ["pipenv", "pytest"]:
                        result["Language"] = "python"

                    # Search code for frameworks
                    code_search_results = search_code_for_patterns(owner, repo, result["Language"])
                    
                    # Update monitoring framework results
                    result["has_newrelic"] = code_search_results["has_newrelic"]
                    result["has_micrometer"] = code_search_results["has_micrometer"]
                    result["has_prometheus"] = code_search_results["has_prometheus"]
                    result["has_aws_lambda_powertools"] = code_search_results["has_aws_lambda_powertools"]
                    result["monitoring_frameworks"] = ",".join(code_search_results["monitoring_frameworks"]) if code_search_results["monitoring_frameworks"] else None
                    result["logging_frameworks"] = ",".join(code_search_results["logging_frameworks"]) if code_search_results["logging_frameworks"] else None

                    # Set MANUAL_CASE if we found any monitoring frameworks
                    if (result["has_newrelic"] or result["has_micrometer"] or 
                        result["has_prometheus"] or result["has_aws_lambda_powertools"]):
                        result["MANUAL_CASE"] = True

                    # Update NR_YES if we found New Relic in code
                    if result["has_newrelic"]:
                        result["NR_YES"] = True
                        result["NO_APM"] = False

                    # Update NO_APM if we found any monitoring frameworks
                    if (result["has_micrometer"] or result["has_prometheus"] or 
                        result["has_aws_lambda_powertools"]):
                        result["NO_APM"] = False

                    # Special case for Go
                    if result["Language"].lower() in ["go", "golang"]:
                        result["MANUAL_CASE"] = True

                if asv_value is None:
                    print(f"Not Found ASV: {result}")
                else:
                    print(f"Found ASV: {asv_value}: {result}")
            else:
                print(f"Could not read Bogiefile content for {github_url}")
                result["NO_APM"] = True

        except ValueError as ve:
            print(f"URL parsing error for {github_url}: {ve}")
        except Exception as e:
            print(f"Error processing {github_url}: {e}")

        return result
    except Exception as e:
        print(f"Unexpected error in process_row: {e}")
        return {
            "Repository": row.get("Repository", "Unknown"),
            "ASV": None,
            "OTEL_YES": False,
            "NR_YES": False,
            "NO_APM": True,
            "Language": None,
            "flavor": None,
            "logging_frameworks": None,
            "monitoring_frameworks": None
        }
        

def display_progress_bar(current, total, start_time, prefix='Processing', length=50):
    """Display a simple progress bar with percentage and time estimate"""
    # Only update progress every 30 seconds to avoid excessive output
    global last_progress_time
    current_time = time.time()
    if current_time - last_progress_time < 30 and current < total:
        return

    last_progress_time = current_time

    percent = min(100, int(100 * current / total)) if total > 0 else 0
    filled_length = int(length * current / total) if total > 0 else 0
    bar = '█' * filled_length + '-' * (length - filled_length)

    # Calculate rate and ETA
    elapsed_time = current_time - start_time
    rate = current / elapsed_time if elapsed_time > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0

    # Format time nicely
    mins = int(remaining // 60)
    secs = int(remaining % 60)

    # Print the progress bar
    print(f"\r{prefix}: |{bar}| {percent}% Complete ({current}/{total}) ETA: {mins}m {secs}s", end='\r')
    sys.stdout.flush()

    # Print a newline when complete
    if current >= total:
        print("\nProcessing complete!")
    
def process_chunk(chunk_tuple):
    """Process a chunk of rows from the DataFrame"""
    index, chunk = chunk_tuple
    chunk_len = len(chunk)
    print(f"Processing chunk {index} with {chunk_len} rows")

    # Define default values for fields
    field_defaults = {
        'ASV': None, 
        'OTEL_YES': False, 
        'NR_YES': False, 
        'NO_APM': True,
        'Language': None,
        'Deployment': None,
        'SearchText': None,
        'flavor': None,
        'MANUAL_CASE': False,
        'has_newrelic': False,
        'has_micrometer': False,
        'has_prometheus': False,
        'has_aws_lambda_powertools': False,
        'has_goblet': False,
        'logging_frameworks': None,
        'monitoring_frameworks': None
    }

    # Process each row individually
    result = chunk.copy()
    processed_count = 0

    # Save initial time for this chunk processing
    chunk_start_time = time.time()

    for idx in result.index:
        try:
            # Process each row and update result DataFrame
            row_result = process_row(result.loc[idx])
            for field, value in row_result.items():
                if field in result.columns:
                    result.at[idx, field] = value
            
            # Update processed count and maybe show progress
            processed_count += 1
        except Exception as e:
            print(f"Error in chunk {index}, row {idx}: {e}")
            # Set default values on error
            for field, default in field_defaults.items():
                result.at[idx, field] = default
            
            # Still count as processed even if there was an error
            processed_count += 1

    return (index, result)


def process_csv_and_extract_asv_parallel(csv_file, max_workers=20):
    """Process CSV file to extract ASV information in parallel"""
    global last_progress_time
    last_progress_time = time.time()  # Initialize progress timer

    print(f"Reading CSV from {csv_file}")
    try:
        # Read URLs as a single column without headers
        df = pd.read_csv(csv_file, names=["Repository"], header=None)
        if "Repository" not in df.columns:
            print(f"Error: Required column 'Repository' not found in {csv_file}")
            return pd.DataFrame()

        # Total rows for progress tracking
        total_rows = len(df)

        # If ASV column doesn't exist, create it
        if "ASV" not in df.columns:
            df["ASV"] = None

        # Add the new columns for OTEL, New Relic, and NO_APM flags
        if "OTEL_YES" not in df.columns:
            df["OTEL_YES"] = False
        if "NR_YES" not in df.columns:
            df["NR_YES"] = False
        if "NO_APM" not in df.columns:
            df["NO_APM"] = True

        # Add the new columns for Language and flavor
        if "Language" not in df.columns:
            df["Language"] = None
        if "flavor" not in df.columns:
            df["flavor"] = None

        # Add the new columns for monitoring framework detection
        if "has_newrelic" not in df.columns:
            df["has_newrelic"] = False
        if "has_micrometer" not in df.columns:
            df["has_micrometer"] = False
        if "has_prometheus" not in df.columns:
            df["has_prometheus"] = False
        if "has_aws_lambda_powertools" not in df.columns:
            df["has_aws_lambda_powertools"] = False
        if "has_goblet" not in df.columns:
            df["has_goblet"] = False

        # Add new columns for logging and monitoring frameworks
        if "logging_frameworks" not in df.columns:
            df["logging_frameworks"] = None
        if "monitoring_frameworks" not in df.columns:
            df["monitoring_frameworks"] = None

        # Create chunks based on max_workers - don't make chunks too small
        chunk_size = max(1, min(50, len(df) // max_workers))
        num_chunks = (len(df) + chunk_size - 1) // chunk_size
        actual_workers = min(
            max_workers, num_chunks
        )  # Don't use more workers than chunks

        print(
            f"Processing {len(df)} rows with {actual_workers} workers in {num_chunks} chunks"
        )

        # Split DataFrame into chunks
        chunks = np.array_split(df, num_chunks)
        indexed_chunks = [(i, chunk) for i, chunk in enumerate(chunks)]

        # Process chunks in parallel using ThreadPoolExecutor
        processed_chunks = OrderedDict()

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=actual_workers
        ) as executor:
            # Submit all chunks for processing
            future_to_index = {
                executor.submit(process_chunk, item): item[0] for item in indexed_chunks
            }

            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_index):
                try:
                    idx, result_chunk = future.result()
                    processed_chunks[idx] = result_chunk

                    # Update progress after each chunk completes
                    completed_rows = sum(
                        len(processed_chunks[i])
                        for i in processed_chunks
                        if i in processed_chunks
                    )
                    display_progress_bar(
                        completed_rows,
                        total_rows,
                        start_time,
                        "Processing repositories",
                    )
                except Exception as e:
                    print(f"\nError processing chunk: {e}")

        # Combine results in original order
        ordered_results = pd.DataFrame()
        for i in range(len(processed_chunks)):
            if i in processed_chunks:
                ordered_results = pd.concat(
                    [ordered_results, processed_chunks[i]], ignore_index=False
                )

        # Show final progress
        display_progress_bar(
            len(ordered_results), total_rows, start_time, "Processing repositories"
        )

        # Calculate and display processing statistics
        end_time = time.time()
        total_time = end_time - start_time
        rows_per_second = len(ordered_results) / total_time if total_time > 0 else 0

        print(f"\nTotal elements processed: {len(ordered_results)}")
        print(f"Total processing time: {total_time:.2f} seconds")
        print(f"Processing rate: {rows_per_second:.2f} rows/second")

        return ordered_results

    except Exception as e:
        # Stop the progress monitoring if there's an error
        progress_active = False
        print(f"\nError in process_csv_and_extract_asv_parallel: {e}")
        return pd.DataFrame()


def write_data(data):
    """Save the processed data to output file"""
    try:
        # Check if data is empty
        if data.empty:
            print("\033[93m⚠️ Warning: No data to write to output file\033[0m")
            return

        # Use absolute path for output file
        output_path = os.path.abspath(OUTPUT_FILE)
        print(f"Writing results to {output_path}")

        # Make sure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"Created output directory: {output_dir}")
            except Exception as e:
                print(
                    f"\033[91m❌ Error creating output directory {output_dir}: {e}\033[0m"
                )
                return

        # Define standard columns - these should be in the output even if they're all None
        standard_columns = [
            "Repository",
            "ASV",
            "OTEL_YES",
            "NR_YES",
            "NO_APM",
            "Language",
            "flavor",
            "MANUAL_CASE",
            "has_newrelic",
            "has_micrometer",
            "has_prometheus",
            "has_aws_lambda_powertools",
            "has_goblet",
            "logging_frameworks",
            "monitoring_frameworks"
        ]

        # Create a new DataFrame to ensure we have full control over the columns and their order
        output_data = pd.DataFrame()

        # First, copy all columns that exist in both standard_columns and data
        for col in standard_columns:
            if col in data.columns:
                output_data[col] = data[col]
            else:
                print(f"Adding missing standard column '{col}'")
                output_data[col] = None

        # Then add any additional columns from the original data that weren't in standard_columns
        # This ensures we don't lose any data that might be useful
        for col in data.columns:
            if col not in standard_columns:
                print(f"Adding extra column '{col}' from data")
                output_data[col] = data[col]

        # Write the new DataFrame to CSV - all columns will be included in the order defined
        print(
            f"Writing {len(output_data)} rows with {len(output_data.columns)} columns"
        )
        output_data.to_csv(output_path, index=False, mode="a")
        print(f"\033[92m✓ Successfully wrote data to {output_path}\033[0m")

    except Exception as e:
        print(f"\033[91m❌ Error writing data to {OUTPUT_FILE}: {e}\033[0m")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Debug information: DataFrame columns = {list(data.columns)}")
        print(f"Try setting an absolute path for the output file using the -o option")


def check_github_rate_limits():
    """Check current GitHub API rate limits and print status"""
    try:
        response = requests.get(f"{api_base_url}/rate_limit", headers=headers)
        if response.status_code == 200:
            data = response.json()
            core_limits = data.get("resources", {}).get("core", {})
            remaining = core_limits.get("remaining", 0)
            limit = core_limits.get("limit", 0)
            reset_time = core_limits.get("reset", 0)
            reset_datetime = datetime.fromtimestamp(reset_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(f"GitHub API Rate Limit Status:")
            print(f" - {remaining}/{limit} requests remaining")
            print(f" - Resets at: {reset_datetime}")

            return remaining, reset_time
        else:
            print(f"Failed to check rate limits: {response.status_code}")
            return None, None
    except Exception as e:
        print(f"Error checking rate limits: {e}")
        return None, None


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Extract ASV information from GitHub repositories"
    )
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        default="Repo_url.csv",
        help="Input CSV file containing repository URLs (default: Repo_url.csv)",
    )
    parser.add_argument(
        "-m",
        "--max-workers",
        type=int,
        default=15,
        help="Maximum number of worker threads (default: 15)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=OUTPUT_FILE,
        help=f"Output CSV file (default: {OUTPUT_FILE})",
    )

    args = parser.parse_args()

    print("Starting ASV extraction process...")

    # Use the input file from command line arguments
    input_csv = args.input

    # Check if GitHub token is set
    if not os.environ.get("GITHUB_TOKEN"):
        print(
            "⚠️⚠️⚠️ WARNING: GITHUB_TOKEN not set! Rate limited to 60 req/hr. Set token for better experience ⚠️⚠️⚠️"
        )

    # Check initial rate limits
    remaining, reset_time = check_github_rate_limits()
    if remaining is not None:
        rate_limit_remaining = remaining
        rate_limit_reset_time = reset_time

    # Set the output file path
    output_file = args.output
    print(f"Using output file: {output_file}")

    # For backwards compatibility with existing code
    # that might reference the module-level OUTPUT_FILE
    if output_file != OUTPUT_FILE:
        # Use a function to avoid global keyword issues
        def update_output_file():
            global OUTPUT_FILE
            OUTPUT_FILE = output_file

        update_output_file()

    # Process the CSV file
    print(f"Using input file: {input_csv}")
    results_df = process_csv_and_extract_asv_parallel(
        input_csv, max_workers=args.max_workers
    )

    # Write the results
    if not results_df.empty:
        print(f"Processed {len(results_df)} repositories")
        write_data(results_df)
    else:
        print("No results to write")

    # Check final rate limit status
    check_github_rate_limits()