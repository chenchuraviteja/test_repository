#!/usr/bin/env python3
"""
GitHub Repository Analyzer

This script analyzes GitHub repositories to detect if they use custom metrics or spans
through libraries like Micrometer or New Relic across various languages.
"""
import os
import sys
import json
import re
import requests
import pandas as pd
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

class GitHubRepoAnalyzer:
    """Main class for analyzing GitHub repositories"""

    def __init__(self, github_token=None):
        """Initialize with optional GitHub token for API authentication"""
        self.headers = {
            "Accept": "application/vnd.github+json"
        }

        self.api_base_url = "https://github.cloud.capitalone.com/api/v3"
        
        # Configure GitHub token if available
        if github_token is None:
            github_token = os.environ.get("GITHUB_TOKEN")
            
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

    def extract_repo_info(self, github_url):
        """Extract owner and repo name from GitHub URL"""
        parsed_url = urlparse(github_url)
        path_parts = parsed_url.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            raise ValueError("Invalid GitHub URL format. Expected format: https://github.com/owner/repo")
        
        return path_parts[0], path_parts[1]

    def get_repo_language(self, owner, repo):
        """Get the primary language of a GitHub repository"""
        api_url = f"{self.api_base_url}/repos/{owner}/{repo}"
        
        response = requests.get(api_url, headers=self.headers)
        
        if response.status_code != 200:
            print(f"Error getting repository info: {response.status_code}")
            print(f"Response: {response.text}")
            return None
        
        repo_data = response.json()
        return repo_data.get("language")

    def download_file(self, owner, repo, file_path):
        """Download a specific file from the repository"""
        api_url = f"{self.api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
        
        response = requests.get(api_url, headers=self.headers)
        
        if response.status_code != 200:
            print(f"No {file_path} found or error accessing it: {response.status_code}")
            return None
        
        content_data = response.json()
        if "content" in content_data:
            import base64
            content = base64.b64decode(content_data["content"]).decode('utf-8')
            return content
        
        return None

    def check_java_libraries(self, owner, repo):
        """Check Java repositories for Micrometer or New Relic libraries"""
        pom_content = self.download_file(owner, repo, "pom.xml")
        if not pom_content:
            print("Could not find or access pom.xml in the repository.")
            return {
                "micrometer": False,
                "newrelic": False
            }
        
        has_micrometer, has_newrelic = self._check_libraries_in_pom(pom_content)
        
        return {
            "micrometer": has_micrometer, 
            "newrelic": has_newrelic
        }

    def _check_libraries_in_pom(self, pom_content):
        """Check if pom.xml contains Micrometer or New Relic libraries"""
        has_micrometer = False
        has_newrelic = False
        
        # First try to parse as XML
        try:
            # Add a root element to handle multi-module projects
            wrapped_content = f"<root>{pom_content}</root>"
            root = ET.fromstring(wrapped_content)
            
            # Look for dependencies
            dependencies = root.findall(".//dependency")
            for dep in dependencies:
                group_id = dep.find("groupId")
                artifact_id = dep.find("artifactId")
                
                if group_id is not None and artifact_id is not None:
                    # Check for Micrometer
                    if "micrometer" in group_id.text.lower() or "micrometer" in artifact_id.text.lower():
                        has_micrometer = True
                    
                    # Check for New Relic
                    if "newrelic" in group_id.text.lower() or "newrelic" in artifact_id.text.lower():
                        has_newrelic = True
        except ET.ParseError:
            # If XML parsing fails, fallback to regex
            print("XML parsing failed, falling back to regex pattern matching")
            
            # Check for Micrometer
            if re.search(r'<groupId>io\.micrometer</groupId>|<artifactId>micrometer', pom_content, re.IGNORECASE):
                has_micrometer = True
            
            # Check for New Relic
            if re.search(r'<groupId>com\.newrelic</groupId>|<artifactId>newrelic', pom_content, re.IGNORECASE):
                has_newrelic = True
        
        return has_micrometer, has_newrelic

    def check_nodejs_libraries(self, owner, repo):
        """Check if a Node.js/TypeScript repository has New Relic dependencies"""
        # Check package.json for New Relic dependencies
        package_json = self.download_file(owner, repo, "package.json")
        if not package_json:
            print("Could not find or access package.json in the repository.")
            return {"newrelic": False}
        
        has_newrelic = False
        
        try:
            package_data = json.loads(package_json)
            
            # Check dependencies and devDependencies for New Relic
            dependencies = package_data.get("dependencies", {})
            dev_dependencies = package_data.get("devDependencies", {})
            
            # Check for New Relic in dependencies
            for dep_name in dependencies:
                if "newrelic" in dep_name.lower():
                    has_newrelic = True
                    break
            
            # Check for New Relic in devDependencies if not found in dependencies
            if not has_newrelic:
                for dep_name in dev_dependencies:
                    if "newrelic" in dep_name.lower():
                        has_newrelic = True
                        break
                    
        except json.JSONDecodeError:
            print("Error parsing package.json, falling back to pattern matching")
            if re.search(r'[\'\"](newrelic|@newrelic)[\'\"]: [\'\"](\\^|~|>=)?\\d', package_json, re.IGNORECASE):
                has_newrelic = True
        
        # If not found in package.json, check for imports in key files
        if not has_newrelic:
            has_newrelic = self._check_nodejs_imports(owner, repo)
        
        return {"newrelic": has_newrelic}
    
    def _check_nodejs_imports(self, owner, repo):
        """Check common JavaScript/TypeScript files for New Relic imports"""
        common_js_files = [
        "index.js", "app.js", "server.js", "src/main.js",
        "index.ts", "app.ts", "server.ts", "src/main.ts"
        ]

        for file_path in common_js_files:
            content = self.download_file(owner, repo, file_path)
            if content and re.search(r'(require|import).*[\'\"](newrelic|@newrelic)', content, re.IGNORECASE):
                return True
        
        return False

    def check_python_libraries(self, owner, repo):
        """Check if a Python repository uses 'newrelic' or 'c1-corpevents' dependencies"""
        result = {
            "newrelic": False,
            "c1-corpevents": False
        }

        libraries = ["newrelic", "c1-corpevents"]

        for lib in libraries:
            lib_pattern = re.escape(lib)

            # Check in requirements.txt
            req_content = self.download_file(owner, repo, "requirements.txt")
            if req_content:
                if re.search(rf'{lib_pattern}[=><~]', req_content, re.IGNORECASE) or \
                re.search(rf'^{lib_pattern}$', req_content, re.IGNORECASE | re.MULTILINE):
                    result[lib] = True
                    continue

            # Check in setup.py
            if not result[lib]:
                setup_content = self.download_file(owner, repo, "setup.py")
                if setup_content and lib in setup_content.lower():
                    if re.search(rf'[\'"](install_requires|requires)[\'"]:\s*.*?[\'"]{lib_pattern}', setup_content, re.IGNORECASE):
                        result[lib] = True
                        continue

            # Check in Pipfile
            if not result[lib]:
                pipfile_content = self.download_file(owner, repo, "Pipfile")
                if pipfile_content and lib in pipfile_content.lower():
                    result[lib] = True
                    continue

            # Check in pyproject.toml
            if not result[lib]:
                pyproject_content = self.download_file(owner, repo, "pyproject.toml")
                if pyproject_content and lib in pyproject_content.lower():
                    if re.search(rf'(dependencies|requires)\s*=\s*\[.*[\'"]{lib_pattern}', pyproject_content, re.IGNORECASE):
                        result[lib] = True

        return result

    def has_custom_metrics_or_spans(self, github_url):
        """
        Main entry point: Analyze a GitHub repository to check if it uses
        custom metrics or spans through libraries like Micrometer or New Relic
        """
        try:
            owner, repo = self.extract_repo_info(github_url)
            print(f"Analyzing repository: {owner}/{repo}")
            
            language = self.get_repo_language(owner, repo)
            print(f"Repository primary language: {language if language else 'Unknown'}")
            
            result = {
                "repository": f"{owner}/{repo}",
                "language": language,
                "has_custom_metrics": False,
                "libraries": {}
            }
            
            # Analyze based on language
            if language:
                language_lower = language.lower()
                
                if language_lower == "java":
                    print("This is a Java repository. Checking for Micrometer and New Relic...")
                    libs = self.check_java_libraries(owner, repo)
                    result["libraries"] = libs
                    result["has_custom_metrics"] = any(libs.values())
                    
                elif language_lower in ["javascript", "typescript", "nodejs", "node"]:
                    print(f"This is a {language} repository. Checking for New Relic...")
                    libs = self.check_nodejs_libraries(owner, repo)
                    result["libraries"] = libs
                    result["has_custom_metrics"] = any(libs.values())
                    
                elif language_lower == "python":
                    print("This is a Python repository. Checking for New Relic...")
                    libs = self.check_python_libraries(owner, repo)
                    result["libraries"] = libs
                    result["has_custom_metrics"] = any(libs.values())
                    
                else:
                    print(f"This is a {language} repository. No analysis configured for this language.")
            else:
                print("Could not determine repository language.")
                
            return result
            
        except ValueError as e:
            print(f"Error: {e}")
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            
        # Return default result on error
        return {
            "repository": github_url,
            "language": None,
            "has_custom_metrics": False,
            "libraries": {}
        }
    
def main():
    """CLI entry point – process a CSV full of GitHub repo URLs."""

    if len(sys.argv) != 2:
        print("Usage: python github_repo_analyzer.py <path_to_repos.csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    df = pd.read_csv(csv_path)

    if "repo_url" not in df.columns:
        print("✖  Column 'repo_url' not found in the CSV file.")
        sys.exit(1)

    analyzer = GitHubRepoAnalyzer()

    discovered_libs: list[str] | None = None

    for idx, repo_url in enumerate(df["repo_url"]):
        print(f"[{idx+1}/{len(df)}] Analyzing {repo_url} …", end="", flush=True)
        try:
            result = analyzer.has_custom_metrics_or_spans(repo_url)
        except Exception as exc:
            print(f"ERROR: {exc}")
            continue

        df.at[idx, "language"] = result["language"]
        df.at[idx, "has_custom_metrics"] = result["has_custom_metrics"]

        if discovered_libs is None:
            discovered_libs = list(result["libraries"])
            for lib_name in discovered_libs:
                if lib_name not in df.columns:
                    df[lib_name] = False     # default value

        for lib_name, present in result["libraries"].items():
            df.at[idx, lib_name] = present

        print("==============done============")

    df.to_csv(csv_path, index=False)
    print(f"\n✓ All done. Updated CSV saved to {csv_path}")

if __name__ == "__main__":
    main()
