import os
import pandas as pd
import re
import shutil
import stat
from git import Repo
from ruamel.yaml import YAML
import concurrent.futures

GITHUB_URL_COLUMN = 'github_url'
BOGIFILE_NAME = 'Bogiefile'

def clone_repo(github_url, repo_dir):
    try:
        github_url = re.sub(r"/tree/.*$", "", github_url)
        print(f"Cloning: {github_url}")
        Repo.clone_from(github_url, repo_dir, depth=1)
        return True
    except Exception as e:
        print(f"Error cloning {github_url}: {e}")
        return False

def read_yaml_with_empty_lines(file_path):
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 1000
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.default_flow_style = False
    yaml.allow_duplicate_keys = True

    with open(file_path, 'r') as file:
        return yaml.load(file)

def find_asv_recursively(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == 'asv':
                return value
            elif isinstance(value, (dict, list)):
                result = find_asv_recursively(value)
                if result is not None:
                    return result
    elif isinstance(data, list):
        for item in data:
            result = find_asv_recursively(item)
            if result is not None:
                return result
    return None

def check_bogiefile_for_asv(repo_dir):
    bogiefile_path = os.path.join(repo_dir, BOGIFILE_NAME)
    if os.path.exists(bogiefile_path):
        try:
            yaml_data = read_yaml_with_empty_lines(bogiefile_path)
            return find_asv_recursively(yaml_data)
        except Exception as e:
            print(f"YAML read error in {BOGIFILE_NAME}: {e}")
    return None

def onerror(func, path, exc_info):
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise

def process_repo(index, github_url):
    repo_dir = os.path.join(os.getcwd(), f"repo_{index}")
    asv_value = None
    try:
        if clone_repo(github_url, repo_dir):
            asv_value = check_bogiefile_for_asv(repo_dir)
    except Exception as e:
        print(f"Error processing {github_url}: {e}")
    finally:
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir, onerror=onerror)
    return {'github_url': github_url, 'asv': asv_value}

def process_csv_and_extract_asv_parallel(csv_file, max_workers=20):
    df = pd.read_csv(csv_file)
    github_urls = df[GITHUB_URL_COLUMN].dropna().tolist()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_repo, idx, re.sub(r"/tree/.*$", "", url)): idx
            for idx, url in enumerate(github_urls)
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Thread error: {e}")

    pd.DataFrame(results).to_csv('asv_results.csv', index=False)
    print("✅ Finished! Saved to 'asv_results.csv'")

if __name__ == "__main__":
    process_csv_and_extract_asv_parallel('github.csv', max_workers=20)
