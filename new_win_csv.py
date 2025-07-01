#!/usr/bin/env python3
"""
Enhanced GitHub Repository Analyzer with CSV support

This script analyzes GitHub repositories to:
1. Identify the primary language
2. Detect if the repo uses custom metrics or spans
3. Check if it can be supported by OpenTelemetry auto-instrumentation
4. Identify if it's a Golang repository
5. Provide appropriate guidance based on the findings

Now supports both direct URL input and CSV file input with URL column
"""

import os
import sys
import json
import re
import requests
import csv
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

class GitHubRepoAnalyzer:
    """Main class for analyzing GitHub repositories with enhanced Python support"""

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
        
        # Load supported frameworks for all languages
        self.java_frameworks = self._parse_java_frameworks()
        self.node_frameworks = self._parse_node_frameworks()
        self.python_frameworks = self._parse_python_frameworks()

    def _parse_java_frameworks(self):
        """Parse supported Java frameworks data"""
        return {
            "libraries": ["spring", "hibernate", "apache httpclient", "jetty", "tomcat"],
            "app_servers": ["tomcat", "jetty", "wildfly", "jboss", "websphere", "weblogic"],
            "jvms": ["openjdk", "oracle hotspot", "ibm", "openj9", "zulu"]
        }

    def _parse_node_frameworks(self):
        """Parse supported Node.js frameworks data"""
        return {
            "raw_frameworks": ["express", "koa", "hapi", "restify", "fastify", "http", "mongodb", "mysql", "pg", "redis", "grpc"],
            "aliases": {
                "express": ["express"],
                "koa": ["koa"],
                "hapi": ["hapi", "@hapi/hapi"],
                "restify": ["restify"],
                "fastify": ["fastify"],
                "http": ["http", "https"],
                "mongodb": ["mongodb"],
                "mysql": ["mysql", "mysql2"],
                "pg": ["pg", "postgresql"],
                "redis": ["redis", "ioredis"],
                "grpc": ["grpc", "@grpc/grpc-js"]
            }
        }

    def _parse_python_frameworks(self):
        """Parse supported Python frameworks data (from python_new.py)"""
        return {
            "raw_frameworks": [
                "openai", "vertexai", "aio-pika", "aiohttp", "aiokafka", "aiopg", "asgi", 
                "asyncpg", "boto", "boto3", "botocore", "cassandra", "celery", "click", 
                "confluent-kafka", "django", "elasticsearch", "falcon", "fastapi", "flask", 
                "grpc", "httpx", "jinja2", "kafka", "mysql", "pika", "psycopg", "pymemcache", 
                "pymongo", "pymssql", "pymysql", "pyramid", "redis", "requests", "sqlalchemy", 
                "starlette", "system-metrics", "tornado", "tortoiseorm", "urllib3"
            ],
            "aliases": {
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
                "urllib3": ["urllib3"]
            }
        }

    # Common utility methods
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
            return None
        
        content_data = response.json()
        if "content" in content_data:
            import base64
            content = base64.b64decode(content_data["content"]).decode('utf-8', errors='replace')
            return content
        
        return None

    # Custom metrics detection methods (enhanced with code pattern checks)
    def check_custom_metrics(self, owner, repo, language):
        """Check if repository uses custom metrics or spans"""
        language_lower = language.lower() if language else ""
        
        if language_lower == "java":
            return self._check_java_custom_metrics(owner, repo)
        elif language_lower in ["javascript", "typescript", "nodejs", "node"]:
            return self._check_nodejs_custom_metrics(owner, repo)
        elif language_lower == "python":
            return self._check_python_custom_metrics(owner, repo)
        elif language_lower == "go":
            return {"has_custom_metrics": False, "reason": "Golang typically requires manual instrumentation"}
        
        return {"has_custom_metrics": False, "reason": "Language not analyzed for custom metrics"}

    def _check_java_custom_metrics(self, owner, repo):
        """Check Java repositories for Micrometer or New Relic libraries and config files"""
        result = {
            "micrometer": False,
            "newrelic": False,
            "telemetry_sdk": False,
            "config_files": [],
            "patterns_found": []
        }

        # Check pom.xml or build.gradle
        pom_content = self.download_file(owner, repo, "pom.xml")
        if pom_content:
            # Check for dependencies in pom.xml
            if re.search(r'<groupId>io\.micrometer</groupId>|<artifactId>micrometer', pom_content, re.IGNORECASE):
                result["micrometer"] = True
            if re.search(r'<groupId>com\.newrelic</groupId>|<artifactId>newrelic', pom_content, re.IGNORECASE):
                if "telemetry" in pom_content.lower():
                    result["telemetry_sdk"] = True
                else:
                    result["newrelic"] = True

        # Check Java config files
        config_files = ["logback.xml", "log4j.xml", "log4j2.xml"]
        for config_file in config_files:
            content = self.download_file(owner, repo, config_file)
            if content and "newrelic" in content.lower():
                result["config_files"].append(config_file)
                result["newrelic"] = True

        # Check Java source files for imports
        java_files = [
            "src/main/java/Main.java",
            "src/main/java/Application.java",
            "src/main/java/App.java"
        ]
        
        patterns_to_check = [
            (r'import com\.newrelic\.telemetry\.', "New Relic telemetry import"),
            (r'import com\.newrelic\.telemetry\.metrics\.', "New Relic metrics import"),
            (r'new TelemetryClient\(', "TelemetryClient usage"),
            (r'new MetricBuffer\(', "MetricBuffer usage")
        ]

        for file_path in java_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                for pattern, pattern_name in patterns_to_check:
                    if re.search(pattern, content):
                        result["telemetry_sdk"] = True
                        result["patterns_found"].append(f"{pattern_name} in {file_path}")

        return {
            "has_custom_metrics": result["micrometer"] or result["newrelic"] or result["telemetry_sdk"],
            "libraries": {
                "micrometer": result["micrometer"],
                "newrelic": result["newrelic"],
                "newrelic-telemetry-sdk": result["telemetry_sdk"]
            },
            "config_files": result["config_files"],
            "patterns_found": result["patterns_found"],
            "reason": "Micrometer or New Relic detected" if (result["micrometer"] or result["newrelic"] or result["telemetry_sdk"]) else "No custom metrics libraries detected"
        }

    def _check_nodejs_custom_metrics(self, owner, repo):
        """Check Node.js repositories for New Relic libraries and usage patterns"""
        result = {
            "newrelic": False,
            "telemetry_sdk": False,
            "patterns_found": []
        }

        # Check package.json first
        package_json = self.download_file(owner, repo, "package.json")
        if package_json:
            try:
                package_data = json.loads(package_json)
                for dep_type in ["dependencies", "devDependencies"]:
                    for dep_name in package_data.get(dep_type, {}):
                        if "newrelic" in dep_name.lower():
                            if "telemetry" in dep_name.lower():
                                result["telemetry_sdk"] = True
                            else:
                                result["newrelic"] = True
            except json.JSONDecodeError:
                pass

        # Check JS/TS files for patterns
        js_files = [
            "index.js", "app.js", "server.js", "main.js",
            "src/index.js", "src/app.js", "src/server.js", "src/main.js"
        ]
        
        patterns_to_check = [
            (r'new CountMetric\(', "CountMetric usage"),
            (r'new GaugeMetric\(', "GaugeMetric usage"),
            (r'new SummaryMetric\(', "SummaryMetric usage"),
            (r'MetricBatchSender', "MetricBatchSender usage"),
            (r'(import|require)\s*\(?[\'"]newrelic[\'"]\)?', "newrelic import"),
            (r'(import|require)\s*\(?[\'"]@newrelic/telemetry-sdk[\'"]\)?', "telemetry-sdk import")
        ]

        for file_path in js_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                for pattern, pattern_name in patterns_to_check:
                    if re.search(pattern, content):
                        if "telemetry" in pattern_name:
                            result["telemetry_sdk"] = True
                        else:
                            result["newrelic"] = True
                        result["patterns_found"].append(f"{pattern_name} in {file_path}")

        return {
            "has_custom_metrics": result["newrelic"] or result["telemetry_sdk"],
            "libraries": {
                "newrelic": result["newrelic"],
                "@newrelic/telemetry-sdk": result["telemetry_sdk"]
            },
            "patterns_found": result["patterns_found"],
            "reason": "New Relic detected" if (result["newrelic"] or result["telemetry_sdk"]) else "No custom metrics libraries detected"
        }

    def _check_python_custom_metrics(self, owner, repo):
        """Check Python repositories for New Relic libraries and usage patterns"""
        result = {
            "newrelic": False,
            "newrelic_telemetry_sdk": False,
            "patterns_found": []
        }

        # Check dependency files first
        libraries = ["newrelic", "newrelic-telemetry-sdk", "newrelic_telemetry_sdk"]
        dependency_files = ["requirements.txt", "setup.py", "Pipfile", "pyproject.toml"]

        for lib in libraries:
            lib_pattern = re.escape(lib)
            
            for file_name in dependency_files:
                content = self.download_file(owner, repo, file_name)
                if content and re.search(rf'{lib_pattern}[=><~]', content, re.IGNORECASE):
                    result["newrelic"] = True if "newrelic" in lib else result["newrelic"]
                    result["newrelic_telemetry_sdk"] = True if "telemetry" in lib else result["newrelic_telemetry_sdk"]
                    break

        # Check Python files for imports and usage
        python_files = [
            "main.py", "app.py", "server.py",
            "src/main.py", "src/app.py", "src/server.py"
        ]
        
        patterns_to_check = [
            (r'from newrelic_telemetry_sdk import', "newrelic_telemetry_sdk import"),
            (r'import newrelic_telemetry_sdk', "newrelic_telemetry_sdk import"),
            (r'GaugeMetric\(', "GaugeMetric usage"),
            (r'CountMetric\(', "CountMetric usage"),
            (r'SummaryMetric\(', "SummaryMetric usage"),
            (r'MetricClient\(', "MetricClient usage")
        ]

        for file_path in python_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                for pattern, pattern_name in patterns_to_check:
                    if re.search(pattern, content):
                        result["newrelic_telemetry_sdk"] = True
                        result["patterns_found"].append(f"{pattern_name} in {file_path}")

        return {
            "has_custom_metrics": result["newrelic"] or result["newrelic_telemetry_sdk"],
            "libraries": {
                "newrelic": result["newrelic"],
                "newrelic_telemetry_sdk": result["newrelic_telemetry_sdk"]
            },
            "patterns_found": result["patterns_found"],
            "reason": "New Relic detected" if (result["newrelic"] or result["newrelic_telemetry_sdk"]) else "No custom metrics libraries detected"
        }

    # Auto-instrumentation checking methods (unchanged from original)
    def check_auto_instrumentation(self, owner, repo, language):
        """Check if repository can be supported by OpenTelemetry auto-instrumentation"""
        language_lower = language.lower() if language else ""
        
        if language_lower == "java":
            return self._check_java_auto_instrumentation(owner, repo)
        elif language_lower in ["javascript", "typescript", "nodejs", "node"]:
            return self._check_nodejs_auto_instrumentation(owner, repo)
        elif language_lower == "python":
            return self._check_python_auto_instrumentation(owner, repo)
        elif language_lower == "go":
            return {
                "compatible": False,
                "reason": "Golang typically requires manual instrumentation",
                "frameworks": []
            }
        
        return {
            "compatible": False,
            "reason": "Language not supported for auto-instrumentation",
            "frameworks": []
        }

    def _check_java_auto_instrumentation(self, owner, repo):
        """Check Java repositories for auto-instrumentation compatibility"""
        build_files = self._find_java_build_files(owner, repo)
        dependencies, _ = self._extract_java_dependencies(build_files)
        
        detected_frameworks = []
        
        # Match dependencies against known frameworks
        for dep in dependencies:
            full_name = f"{dep['groupId']}:{dep['artifactId']}".lower()
            
            # Check for library frameworks
            for framework in self.java_frameworks["libraries"]:
                keywords = framework.lower().split()
                if any(kw in full_name for kw in keywords):
                    detected_frameworks.append({
                        "framework": framework,
                        "groupId": dep["groupId"],
                        "artifactId": dep["artifactId"],
                        "version": dep["version"]
                    })
            
            # Check for application servers
            for server in self.java_frameworks["app_servers"]:
                keywords = server.lower().split()
                if any(kw in full_name for kw in keywords):
                    detected_frameworks.append({
                        "server": server,
                        "groupId": dep["groupId"],
                        "artifactId": dep["artifactId"],
                        "version": dep["version"]
                    })
        
        return {
            "compatible": len(detected_frameworks) > 0,
            "reason": "Supported frameworks detected" if detected_frameworks else "No supported frameworks detected",
            "frameworks": detected_frameworks
        }

    def _find_java_build_files(self, owner, repo):
        """Find Java build files in the repository"""
        build_files = []
        target_files = ["pom.xml", "build.gradle", "build.gradle.kts"]
        
        for file in target_files:
            content = self.download_file(owner, repo, file)
            if content:
                build_files.append((file, content))
        
        return build_files

    def _extract_java_dependencies(self, build_files):
        """Extract dependencies from Java build files"""
        all_dependencies = []
        parent_info = None
        
        for file_name, content in build_files:
            if file_name == "pom.xml":
                dependencies, parent = self._analyze_pom_xml(content)
                all_dependencies.extend(dependencies)
                if parent and not parent_info:
                    parent_info = parent
            elif file_name in ["build.gradle", "build.gradle.kts"]:
                dependencies = self._analyze_gradle_file(content)
                all_dependencies.extend(dependencies)
        
        return all_dependencies, parent_info

    def _analyze_pom_xml(self, content):
        """Analyze Maven POM file for dependencies"""
        dependencies = []
        parent_info = None
        
        try:
            wrapped_content = f"<root>{content}</root>"
            root = ET.fromstring(wrapped_content)
            
            # Check for parent POM
            parent = root.find(".//parent")
            if parent is not None:
                group_id = parent.find("groupId")
                artifact_id = parent.find("artifactId")
                version = parent.find("version")
                
                if group_id is not None and artifact_id is not None:
                    parent_info = {
                        "groupId": group_id.text,
                        "artifactId": artifact_id.text,
                        "version": version.text if version is not None else "unknown"
                    }
            
            # Extract all dependencies
            deps = root.findall(".//dependency")
            for dep in deps:
                group_id = dep.find("groupId")
                artifact_id = dep.find("artifactId")
                version = dep.find("version")
                
                if group_id is not None and artifact_id is not None:
                    dependency = {
                        "groupId": group_id.text,
                        "artifactId": artifact_id.text,
                        "version": version.text if version is not None else "unknown"
                    }
                    dependencies.append(dependency)
                    
        except ET.ParseError:
            # Fallback to regex
            dependency_pattern = r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?'            
            matches = re.findall(dependency_pattern, content, re.DOTALL)
            for match in matches:
                group_id, artifact_id, version = match
                dependencies.append({
                    "groupId": group_id,
                    "artifactId": artifact_id,
                    "version": version if version else "unknown"
                })
            
            parent_pattern = r'<parent>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
            parent_match = re.search(parent_pattern, content, re.DOTALL)
            if parent_match:
                parent_info = {
                    "groupId": parent_match.group(1),
                    "artifactId": parent_match.group(2),
                    "version": parent_match.group(3)
                }
                
        return dependencies, parent_info

    def _analyze_gradle_file(self, content):
        """Analyze Gradle build file for dependencies"""
        dependencies = []
        dependency_patterns = [
            r'(?:implementation|compile)(?:Only)?\s*["\'](.*?):(.+?):(.+?)["\'\'\)]',
            r'(?:implementation|compile)(?:Only)?\s*group:\s*["\'](.*?)["\'\'\)],\s*name:\s*["\'](.*?)["\'\'\)],\s*version:\s*["\'](.*?)["\'\'\)]'
        ]
        
        for pattern in dependency_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if len(match) == 3:
                    group_id, artifact_id, version = match
                    dependencies.append({
                        "groupId": group_id,
                        "artifactId": artifact_id,
                        "version": version
                    })
        
        return dependencies

    def _check_nodejs_auto_instrumentation(self, owner, repo):
        """Check Node.js repositories for auto-instrumentation compatibility"""
        frameworks_used = self._find_nodejs_frameworks(owner, repo)
        supported_frameworks = self._match_nodejs_frameworks(frameworks_used)
        
        return {
            "compatible": len(supported_frameworks) > 0,
            "reason": "Supported frameworks detected" if supported_frameworks else "No supported frameworks detected",
            "frameworks": supported_frameworks
        }

    def _find_nodejs_frameworks(self, owner, repo):
        """Find Node.js frameworks used in the repository"""
        frameworks_used = []
        
        # Analyze package.json
        package_content = self.download_file(owner, repo, "package.json")
        if package_content:
            try:
                package_data = json.loads(package_content)
                for dep_name, version in package_data.get("dependencies", {}).items():
                    frameworks_used.append({
                        "name": dep_name,
                        "version": version,
                        "type": "dependency"
                    })
                for dep_name, version in package_data.get("devDependencies", {}).items():
                    frameworks_used.append({
                        "name": dep_name,
                        "version": version,
                        "type": "devDependency"
                    })
            except json.JSONDecodeError:
                pass
        
        # Check common entry files for imports
        entry_files = ["index.js", "app.js", "server.js", "main.js"]
        for file_path in entry_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                # Look for imports
                imports = re.findall(r'(?:import\s+.*\s+from\s+|require\()[\'"]([^\'"]*)[\'"]', content)
                for import_path in imports:
                    package_name = import_path.split('/')[0]
                    frameworks_used.append({
                        "name": package_name,
                        "source": file_path,
                        "type": "import"
                    })
        
        return frameworks_used

    def _match_nodejs_frameworks(self, frameworks_used):
        """Match used Node.js frameworks against supported ones"""
        supported_frameworks = []
        
        for framework in frameworks_used:
            framework_name = framework["name"].lower()
            
            # Check against aliases
            for otel_framework, aliases in self.node_frameworks["aliases"].items():
                if any(alias in framework_name for alias in aliases):
                    supported_frameworks.append({
                        "framework": otel_framework,
                        "package": framework["name"],
                        "version": framework.get("version", "unknown"),
                        "type": framework.get("type", "unknown")
                    })
                    break
            
            # Check against raw framework names
            for raw_framework in self.node_frameworks["raw_frameworks"]:
                if raw_framework in framework_name:
                    if not any(sf["framework"] == raw_framework for sf in supported_frameworks):
                        supported_frameworks.append({
                            "framework": raw_framework,
                            "package": framework["name"],
                            "version": framework.get("version", "unknown"),
                            "type": framework.get("type", "unknown")
                        })
        
        return supported_frameworks

    def _check_python_auto_instrumentation(self, owner, repo):
        """Check Python repositories for auto-instrumentation compatibility"""
        frameworks_used, files_analyzed = self._find_python_frameworks(owner, repo)
        supported_frameworks = self._match_python_frameworks(frameworks_used)
        
        return {
            "compatible": len(supported_frameworks) > 0,
            "reason": "Supported frameworks detected" if supported_frameworks else "No supported frameworks detected",
            "frameworks": supported_frameworks,
            "files_analyzed": files_analyzed
        }

    def _find_python_frameworks(self, owner, repo):
        """Find Python frameworks used in the repository"""
        frameworks_used = []
        files_analyzed = []
        
        # Check requirements.txt
        req_content = self.download_file(owner, repo, "requirements.txt")
        if req_content:
            files_analyzed.append("requirements.txt")
            frameworks_used.extend(self._analyze_python_package_file(req_content))
        
        # Check Pipfile
        pipfile_content = self.download_file(owner, repo, "Pipfile")
        if pipfile_content:
            files_analyzed.append("Pipfile")
            frameworks_used.extend(self._analyze_python_package_file(pipfile_content))
        
        # Check common Python files
        python_files = [
            "main.py", "app.py", "server.py",
            "src/main.py", "src/app.py", "src/server.py"
        ]
        
        for file_path in python_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                files_analyzed.append(file_path)
                frameworks_used.extend(self._analyze_python_imports(content, file_path))
        
        return frameworks_used, files_analyzed

    def _analyze_python_package_file(self, content):
        """Analyze Python package files for dependencies"""
        dependencies = []
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '-r', '--')):
                continue
            
            # Extract package name (ignore versions)
            package = re.split(r'[<=>!~]', line)[0].strip()
            package = re.sub(r'\[.*\]', '', package)  # Remove extras
            
            if package:
                dependencies.append({
                    "name": package,
                    "type": "dependency"
                })
        
        return dependencies

    def _analyze_python_imports(self, content, file_path):
        """Analyze Python files for import statements"""
        frameworks_used = []
        
        # Look for import statements
        import_pattern = r'^\s*(?:from|import)\s+([^\s\.]+)'
        imports = re.findall(import_pattern, content, re.MULTILINE)
        
        for import_path in imports:
            package_name = import_path.split('.')[0]
            frameworks_used.append({
                "name": package_name,
                "source": file_path,
                "type": "import"
            })
        
        return frameworks_used

    def _match_python_frameworks(self, frameworks_used):
        """Match used Python frameworks against supported ones"""
        supported_frameworks = []
        
        for framework in frameworks_used:
            framework_name = framework["name"].lower()
            
            # Check against aliases
            for otel_framework, aliases in self.python_frameworks["aliases"].items():
                if any(alias.lower() == framework_name for alias in aliases):
                    supported_frameworks.append({
                        "framework": otel_framework,
                        "package": framework["name"],
                        "type": framework.get("type", "unknown")
                    })
                    break
            
            # Check against raw framework names
            for raw_framework in self.python_frameworks["raw_frameworks"]:
                if raw_framework.lower() == framework_name:
                    if not any(sf["framework"] == raw_framework for sf in supported_frameworks):
                        supported_frameworks.append({
                            "framework": raw_framework,
                            "package": framework["name"],
                            "type": framework.get("type", "unknown")
                        })
        
        return supported_frameworks

    # Main analysis function
    def analyze_repository(self, github_url):
        """Main analysis function that follows the specified steps"""
        try:
            owner, repo = self.extract_repo_info(github_url)
            print(f"\nAnalyzing repository: {owner}/{repo}")
            
            # Step 1: Identify language
            language = self.get_repo_language(owner, repo)
            print(f"Primary language: {language if language else 'Unknown'}")
            
            result = {
                "repository": f"{owner}/{repo}",
                "language": language,
                "is_golang": language and language.lower() == "go",
                "custom_metrics": None,
                "auto_instrumentation": None,
                "recommendation": None,
                "reason": None,
                "details": {}
            }
            
            # Step 2: Check for custom metrics/spans
            if language:
                custom_metrics_result = self.check_custom_metrics(owner, repo, language)
                result["custom_metrics"] = custom_metrics_result["has_custom_metrics"]
                result["details"]["custom_metrics"] = custom_metrics_result
                print(f"Custom metrics/spans detected: {'Yes' if result['custom_metrics'] else 'No'}")
                if result["custom_metrics"]:
                    print(f"  Reason: {custom_metrics_result['reason']}")
                    if custom_metrics_result.get("patterns_found"):
                        print("  Patterns found:")
                        for pattern in custom_metrics_result["patterns_found"]:
                            print(f"    - {pattern}")
            else:
                result["custom_metrics"] = False
                print("Skipping custom metrics check - language not detected")
            
            # Step 3: Check for auto-instrumentation compatibility
            if language:
                auto_instrumentation_result = self.check_auto_instrumentation(owner, repo, language)
                result["auto_instrumentation"] = auto_instrumentation_result["compatible"]
                result["details"]["auto_instrumentation"] = auto_instrumentation_result
                print(f"Auto-instrumentation compatible: {'Yes' if result['auto_instrumentation'] else 'No'}")
                print(f"  Reason: {auto_instrumentation_result['reason']}")
                
                # Add framework details if available
                if "frameworks" in auto_instrumentation_result:
                    print("Detected frameworks:")
                    for fw in auto_instrumentation_result["frameworks"]:
                        print(f"  - {fw.get('framework', fw.get('server', 'Unknown'))}")
            else:
                result["auto_instrumentation"] = False
                print("Skipping auto-instrumentation check - language not detected")
            
            # Step 4: Determine recommendation
            if result["is_golang"]:
                result["recommendation"] = "Use Windsurf for Golang instrumentation"
                result["reason"] = "Golang typically requires manual instrumentation"
            elif result["custom_metrics"]:
                result["recommendation"] = "Use Windsurf for custom metrics/spans"
                result["reason"] = "Custom metrics/spans detected"
            elif result["auto_instrumentation"]:
                result["recommendation"] = "Use OpenTelemetry auto-instrumentation"
                result["reason"] = "Compatible with auto-instrumentation"
                if language.lower() == "python":
                    result["reason"] += f" (Detected: {', '.join(fw['framework'] for fw in auto_instrumentation_result.get('frameworks', []))})"
            else:
                result["recommendation"] = "Use Windsurf"
                result["reason"] = "Not compatible with auto-instrumentation and no custom metrics detected"
            
            return result
            
        except ValueError as e:
            print(f"Error: {e}")
            return {
                "repository": github_url,
                "error": str(e)
            }
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            return {
                "repository": github_url,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            print(f"Unexpected error: {e}")
            return {
                "repository": github_url,
                "error": f"Unexpected error: {str(e)}"
            }

def process_csv(input_file, output_file=None):
    """Process a CSV file containing GitHub URLs"""
    if output_file is None:
        # Create default output filename by adding _analyzed before .csv
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_analyzed{ext}"
    
    analyzer = GitHubRepoAnalyzer()
    
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile, \
         open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        
        reader = csv.DictReader(infile)
        
        # Prepare output fieldnames
        fieldnames = reader.fieldnames + [
            'Primary_Language',
            'Custom_Metrics_Detected',
            'Auto_Instrumentation_Compatible',
            'Recommendation',
            'Reason'
        ]
        
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            github_url = row.get('url') or row.get('github_url') or row.get('repository_url')
            if not github_url:
                print(f"Skipping row - no GitHub URL found: {row}")
                continue
            
            if not github_url.startswith(('http://', 'https://')):
                github_url = f'https://{github_url}'
            
            print(f"\nProcessing: {github_url}")
            result = analyzer.analyze_repository(github_url)
            
            # Update row with analysis results
            row.update({
                'Primary_Language': result.get('language', ''),
                'Custom_Metrics_Detected': 'Yes' if result.get('custom_metrics') else 'No',
                'Auto_Instrumentation_Compatible': 'Yes' if result.get('auto_instrumentation') else 'No',
                'Recommendation': result.get('recommendation', ''),
                'Reason': result.get('reason', '')
            })
            
            writer.writerow(row)
    
    print(f"\nAnalysis complete. Results saved to: {output_file}")

def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python repo_analyzer.py <github_repo_url>")
        print("  python repo_analyzer.py --csv <input_csv_file> [output_csv_file]")
        sys.exit(1)

    if sys.argv[1] == "--csv":
        # CSV mode
        if len(sys.argv) < 3:
            print("Error: Please provide input CSV file")
            print("Usage: python repo_analyzer.py --csv <input_csv_file> [output_csv_file]")
            sys.exit(1)
        
        input_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        process_csv(input_file, output_file)
    else:
        # Single URL mode
        github_url = sys.argv[1]
        analyzer = GitHubRepoAnalyzer()

        # Analyze the repository
        result = analyzer.analyze_repository(github_url)

        # Print final recommendation
        print("\n=== Analysis Results ===")
        print(f"Repository: {result['repository']}")
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Language: {result['language']}")
            print(f"Recommendation: {result['recommendation']}")
            print(f"Reason: {result['reason']}")
            
            # Print detailed findings if available
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