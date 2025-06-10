import os
import pandas as pd
import re
import shutil
import stat
from git import Repo
from ruamel.yaml import YAML

GITHUB_URL_COLUMN = 'github_url'
BOGIFILE_NAME = 'Bogiefile'

def clone_repo(github_url, repo_dir):
    try:
        github_url = re.sub(r"/tree/.*$", "", github_url)
        print(f"Cloning repository: {github_url} into {repo_dir}")
        Repo.clone_from(github_url, repo_dir)
        return True
    except Exception as e:
        print(f"Error cloning repository {github_url}: {e}")
        return False

def read_yaml_with_empty_lines(file_path):
    print(f"Reading YAML from: {file_path}")
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 1000
    yaml.indent(mapping=2, sequence=4, offset=2)

    with open(file_path, 'r') as file:
        data = yaml.load(file)

    return data

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
            asv_value = find_asv_recursively(yaml_data)
            print(f"Extracted ASV: {asv_value}")
            return asv_value
        except Exception as e:
            print(f"Error reading {BOGIFILE_NAME}: {e}")
            return None
    else:
        print(f"No {BOGIFILE_NAME} found in {repo_dir}")
        return None

def onerror(func, path, exc_info):
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise

def process_csv_and_extract_asv(csv_file):
    df = pd.read_csv(csv_file)
    result_data = []
    for index, row in df.iterrows():
        github_url = row[GITHUB_URL_COLUMN]
        print(f"Processing: {github_url}")
        if isinstance(github_url, str):
            repo_dir = os.path.join(os.getcwd(), f"repo_{index}")
            asv_value = None
            if clone_repo(github_url, repo_dir):
                asv_value = check_bogiefile_for_asv(repo_dir)
                shutil.rmtree(repo_dir, onerror=onerror)
            github_url = re.sub(r"/tree/.*$", "", github_url)
            result_data.append({
                'github_url': github_url,
                'asv': asv_value
            })
    
    result_df = pd.DataFrame(result_data)
    result_df.to_csv('asv_results.csv', index=False)
    print("Saved results to 'asv_results.csv'")

if __name__ == "__main__":
    csv_file = 'github.csv'
    process_csv_and_extract_asv(csv_file)
