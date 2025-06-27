#!/usr/bin/env python3
"""
Python OpenTelemetry Compatibility Checker

Mirrors Node.js script structure but for Python packages.
"""
import os
import sys
import re
import requests
from urllib.parse import urlparse


class PythonOtelCompatibilityChecker:
    """Class to check Python repositories for OpenTelemetry auto-instrumentation compatibility"""

    def __init__(self, github_token=None):
        """Initialize with optional GitHub token for API authentication"""
        self.headers = {"Accept": "application/vnd.github+json"}

        if github_token is None:
            github_token = os.environ.get("GITHUB_TOKEN")

        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

        self.supported_frameworks = self.parse_supported_frameworks()

    def parse_supported_frameworks(self):
        """Parse supported frameworks data (similar to Node.js version)"""
        framework_aliases = {
            "openai": ["openai"],
            "vertexai": ["google-cloud-aiplatform"],
            "aio-pika": ["aio_pika"],
            "aiohttp": ["aiohttp"],
            "aiokafka": ["aiokafka"],
            "aiopg": ["aiopg"],
            "asgi": ["asgiref"],
            "asyncpg": ["asyncpg"],
            "boto": ["boto"],
            "boto3": ["boto3"],
            "botocore": ["botocore"],
            "cassandra": ["cassandra-driver", "scylla-driver"],
            "celery": ["celery"],
            "click": ["click"],
            "confluent-kafka": ["confluent-kafka"],
            "django": ["django"],
            "elasticsearch": ["elasticsearch"],
            "falcon": ["falcon"],
            "fastapi": ["fastapi"],
            "flask": ["flask"],
            "grpc": ["grpcio"],
            "httpx": ["httpx"],
            "jinja2": ["jinja2"],
            "kafka": ["kafka-python", "kafka-python-ng"],
            "mysql": ["mysql-connector-python", "mysqlclient"],
            "pika": ["pika"],
            "psycopg": ["psycopg", "psycopg2", "psycopg2-binary"],
            "pymemcache": ["pymemcache"],
            "pymongo": ["pymongo"],
            "pymssql": ["pymssql"],
            "pymysql": ["PyMySQL"],
            "pyramid": ["pyramid"],
            "redis": ["redis"],
            "requests": ["requests"],
            "sqlalchemy": ["sqlalchemy"],
            "starlette": ["starlette"],
            "system-metrics": ["psutil"],
            "tornado": ["tornado"],
            "tortoiseorm": ["tortoise-orm", "pydantic"],
            "urllib3": ["urllib3"],
        }

        return {
            "raw_frameworks": list(framework_aliases.keys()),
            "aliases": framework_aliases,
        }

    def extract_repo_info(self, github_url):
        """Extract owner and repo name from GitHub URL (same as Node.js)"""
        parsed_url = urlparse(github_url)
        path_parts = parsed_url.path.strip("/").split("/")

        if len(path_parts) < 2:
            raise ValueError(
                "Invalid GitHub URL format. Expected format: https://github.com/owner/repo"
            )

        return path_parts[0], path_parts[1]

    def get_repo_language(self, owner, repo):
        """Get the primary language of a GitHub repository (same as Node.js)"""
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        response = requests.get(api_url, headers=self.headers)

        if response.status_code != 200:
            print(f"Error getting repository info: {response.status_code}")
            return None

        return response.json().get("language")

    def download_file(self, owner, repo, file_path):
        """Download a specific file from the repository (same as Node.js)"""
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
        response = requests.get(api_url, headers=self.headers)

        if response.status_code != 200:
            return None

        content_data = response.json()
        if "content" in content_data:
            import base64

            return base64.b64decode(content_data["content"]).decode(
                "utf-8", errors="replace"
            )
        return None

    def analyze_package_file(self, content):
        """Analyze requirements.txt/Pipfile for dependencies (similar to analyze_package_json)"""
        dependencies = []

        # Simple parsing - just get package names
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-r", "--")):
                continue

            # Extract package name (ignore versions)
            package = re.split(r"[<=>~!]", line)[0].strip()
            package = re.sub(r"\[.*\]", "", package)  # Remove extras

            if package:
                dependencies.append({"name": package, "type": "dependency"})

        return dependencies

    def analyze_import_statements(self, content, file_path):
        """Analyze Python file for import statements (similar to Node.js version)"""
        frameworks_used = []

        # Look for import statements
        import_pattern = r"^\s*(?:from|import)\s+([^\s\.]+)"
        imports = re.findall(import_pattern, content, re.MULTILINE)

        for import_path in imports:
            package_name = import_path.split(".")[0]
            frameworks_used.append(
                {"name": package_name, "source": file_path, "type": "import"}
            )

        return frameworks_used

    def find_framework_files(self, owner, repo):
        """Find Python project files in the repository (similar to Node.js version)"""
        frameworks_used = []
        files_analyzed = []

        # Check requirements.txt
        req_content = self.download_file(owner, repo, "requirements.txt")
        if req_content:
            files_analyzed.append("requirements.txt")
            frameworks_used.extend(self.analyze_package_file(req_content))

        # Check Pipfile
        pipfile_content = self.download_file(owner, repo, "Pipfile")
        if pipfile_content:
            files_analyzed.append("Pipfile")
            frameworks_used.extend(self.analyze_package_file(pipfile_content))

        # Check common Python files
        python_files = [
            "main.py",
            "app.py",
            "server.py",
            "src/main.py",
            "src/app.py",
            "src/server.py",
        ]

        for file_path in python_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                files_analyzed.append(file_path)
                frameworks_used.extend(
                    self.analyze_import_statements(content, file_path)
                )

        return frameworks_used, files_analyzed

    def match_frameworks_with_supported(self, frameworks_used):
        """Match used frameworks against supported OpenTelemetry frameworks (same pattern as Node.js)"""
        supported_frameworks = []

        for framework in frameworks_used:
            framework_name = framework["name"].lower()

            # Check against aliases first
            for otel_framework, aliases in self.supported_frameworks["aliases"].items():
                if any(alias.lower() == framework_name for alias in aliases):
                    supported_frameworks.append(
                        {
                            "framework": otel_framework,
                            "package": framework["name"],
                            "type": framework.get("type", "unknown"),
                        }
                    )
                    break

            # Check against raw framework names
            for raw_framework in self.supported_frameworks["raw_frameworks"]:
                if raw_framework.lower() == framework_name:
                    if not any(
                        sf["framework"] == raw_framework for sf in supported_frameworks
                    ):
                        supported_frameworks.append(
                            {
                                "framework": raw_framework,
                                "package": framework["name"],
                                "type": framework.get("type", "unknown"),
                            }
                        )

        return supported_frameworks

    def check_otel_compatibility(self, github_url):
        """Main entry point (same structure as Node.js version)"""
        try:
            owner, repo = self.extract_repo_info(github_url)
            print(f"Analyzing repository: {owner}/{repo}")

            language = self.get_repo_language(owner, repo)
            print(f"Repository primary language: {language if language else 'Unknown'}")

            if not language or language.lower() != "python":
                return {
                    "repository": f"{owner}/{repo}",
                    "language": language,
                    "compatible_with_otel": False,
                    "reason": "Not a Python repository",
                }

            print("Detecting Python frameworks...")
            frameworks_used, files_analyzed = self.find_framework_files(owner, repo)
            supported_frameworks = self.match_frameworks_with_supported(frameworks_used)

            return {
                "repository": f"{owner}/{repo}",
                "language": language,
                "compatible_with_otel": len(supported_frameworks) > 0,
                "supported_frameworks": supported_frameworks,
                "files_analyzed": files_analyzed,
                "reason": (
                    "Compatible" if supported_frameworks else "No supported frameworks"
                ),
            }

        except Exception as e:
            return {
                "repository": github_url,
                "language": None,
                "compatible_with_otel": False,
                "reason": f"Error analyzing repository: {str(e)}",
            }


def main():
    """CLI entry point (same as Node.js version)"""
    if len(sys.argv) != 2:
        print("Usage: python python_otel_compatibility_checker.py <github_repo_url>")
        sys.exit(1)

    github_url = sys.argv[1]
    checker = PythonOtelCompatibilityChecker()
    result = checker.check_otel_compatibility(github_url)

    print("\nResults:")
    print(f"Repository: {result['repository']}")
    print(f"Language: {result['language']}")
    print(f"Compatible: {'Yes' if result['compatible_with_otel'] else 'No'}")
    print(f"Reason: {result['reason']}")

    if result["compatible_with_otel"]:
        print("\nSupported frameworks:")
        for fw in result["supported_frameworks"]:
            print(f"  - {fw['framework']} (package: {fw['package']})")

    print("\nFiles analyzed:")
    for file in result.get("files_analyzed", []):
        print(f"  - {file}")


if __name__ == "__main__":
    main()
