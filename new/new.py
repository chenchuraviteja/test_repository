import logging
import os
import sys
import csv
import json
import re
import requests
import tempfile
import shutil
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from multiprocessing import Pool, cpu_count
import time
from functools import partial
import ruamel.yaml
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, LiteralScalarString
from ruamel.yaml.compat import StringIO
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union, Any


#############################################################
# CONFIGURATION AND CONSTANTS
#############################################################

# General configuration constants
NEW = '.new'
EXECUTED_IN_CODEGENIE = os.environ.get("HOSTNAME") is not None
DOCKER_IMAGE_PATTERN = re.compile(r"FROM\s")
NEW_RELIC_PATTERN = r'(?i)^new[_]?relic.*'

# Supported gear types
ALLOWLISTED_GEARS = ['autocruise-express-service:^3', 'ecs-fargate:^1', 'aws-lambda:^4', 'origami:^2']

# Java specific constants
JAR_FILE_NAME_PATTERN_JAVAOPTS = r'\b[A-Za-z_]*JAVA_OPT[A-Za-z_]+\s*=\s*["\']*-javaagent:[^\s]*otel[-\w]*\.jar[^"\']["\']*'
JAR_FILE_NAME_PATTERN_CMD = r'(CMD).*(otel-javaagent.jar|otel.jar)'

# Docker image patterns
ARTIFACTORY_IMAGE_PATTERN = 'artifactory-edge-staging.cloud.capitalone.com/'
APM_SUPPORTED_IMAGE_PREFIX = 'artifactory-edge-staging.cloud.capitalone.com/bacloudosimages-docker/cof-approved-images/apm'
PLEC_APM_SUPPORTED_IMAGE_PREFIX = 'artifactory-edge-staging.cloud.capitalone.com/baenterprisesharedimages-docker/languages/java'
TOMCAT_SUPPORTED_IMAGE_PREFIX = 'artifactory-edge-staging.cloud.capitalone.com/bacloudosimages-docker/cof-approved-images/tomcat'

# Node.js specific constants
NPM_INSTALL_COMMAND = "RUN npm install @opentelemetry/api @opentelemetry/auto-instrumentations-node\n"
OTEL_EXPORTS_TEMPLATE = """\
RUN export OTEL_TRACES_EXPORTER="otlp" \\
    && export OTEL_METRICS_EXPORTER="otlp" \\
    && export OTEL_EXPORTER_OTLP_ENDPOINT="{endpoint}" \\
    && export OTEL_NODE_RESOURCE_DETECTORS="env,host,os" \\
    && export OTEL_SERVICE_NAME="<your-service-name>" \\
    && export OTEL_RESOURCE_ATTRIBUTES="tags.ASV={asv},tags.BA={ba},tags.COMPONENT={component}" \\
    && export NODE_OPTIONS="--require @opentelemetry/auto-instrumentations-node/register"\n
"""

# Python specific constants
PYTHON_ENVIRONMENT_VARIABLES = [
    
    'ENV OTEL_TRACES_EXPORTER=otlp',
    'ENV OTEL_METRICS_EXPORTER=otlp',
    'ENV OTEL_RESOURCE_ATTRIBUTES="tags.ASV={asv},tags.BA={ba},tags.COMPONENT={component}"'
]


@dataclass
class AnalysisResult:
    repository: str
    language: Optional[str] = None
    repo_accessible: bool = False
    archived: bool = False
    is_golang: bool = False
    custom_metrics: Optional[bool] = None
    auto_instrumentation: Optional[bool] = None
    recommendation: Optional[str] = None
    reason: List[str] = None
    has_newrelic: bool = False
    has_micrometer: bool = False
    has_prometheus: bool = False
    has_aws_lambda_powertools: bool = False
    logging_frameworks: Optional[List[str]] = None
    monitoring_frameworks: Optional[List[str]] = None
    MANUAL_CASE: bool = False
    OTEL_Onboarded: bool = False
    flavor: Optional[str] = None
    supported: bool = False
    details: Dict = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.reason is None:
            self.reason = []


class GitHubRepoAnalyzer:
    """Optimized class for analyzing GitHub repositories with enhanced Python support"""

    SUPPORTED_LANGUAGES = ['java', 'javascript', 'python', 'dotnet', 'go', 'scala', 'kotlin']
    PRIMARY_LANGUAGES = ['java', 'javascript', 'python', 'go']
    SUPPORTED_FLAVORS = [
        "container/aws-batch",
        "data-processing/application",
        "osdg-processing",
        "serverless-function/scheduled-event",
        "serverless-function/push-event",
        "serverless-function/standalone",
        "serverless-function/pull-event",
        "composite-application",
        "serverless-function/composite"
    ]

    def __init__(self, github_token=None):
        """Initialize with optional GitHub token for API authentication"""
        self.headers = {
            "Accept": "application/vnd.github+json"
        }

        self.api_base_url = "https://github.cloud.capitalone.com/api/v3"
        
        if github_token is None:
            github_token = os.environ.get("GITHUB_TOKEN")
            
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"
        
        # Pre-compile regex patterns
        self._compile_regex_patterns()
        
        # Load supported frameworks
        self.frameworks = {
            'java': self._parse_java_frameworks(),
            'node': self._parse_node_frameworks(),
            'python': self._parse_python_frameworks()
        }

        self.logging_frameworks = self._init_logging_frameworks()

    def _compile_regex_patterns(self):
        """Compile all regex patterns for better performance"""
        self.dependency_patterns = {
            'gradle': [
                re.compile(r'(?:implementation|compile)(?:Only)?\s*["\'](.*?):(.+?):(.+?)["\'\'\)]'),
                re.compile(r'(?:implementation|compile)(?:Only)?\s*group:\s*["\'](.*?)["\'\'\)],\s*name:\s*["\'](.*?)["\'\'\)],\s*version:\s*["\'](.*?)["\'\'\)]')
            ],
            'maven': re.compile(r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?'),
            'parent': re.compile(r'<parent>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'),
            'import': re.compile(r'^\s*(?:from|import)\s+([^\s\.]+)', re.MULTILINE),
            'bogiefile_tool': re.compile(r'tool:\s*([\w-]+)', re.MULTILINE),
            'flavor': re.compile(r"flavor:\s*([\w/-]+)"),
            'otel_indicator': re.compile(r"OTEL_")
        }

    def _init_logging_frameworks(self) -> Dict:
        """Initialize logging and monitoring frameworks configuration"""
        return {
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

    def _parse_java_frameworks(self) -> Dict:
        """Parse supported Java frameworks data"""
        return {
            "libraries": ["spring", "spring boot", "hibernate", "apache httpclient", "jetty", "tomcat"],
            "app_servers": ["tomcat", "jetty", "wildfly", "jboss", "websphere", "weblogic"],
            "jvms": ["openjdk", "oracle hotspot", "ibm", "openj9", "zulu"]
        }

    def _parse_node_frameworks(self) -> Dict:
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
    
    def _parse_python_frameworks(self) -> Dict:
        """Parse supported Python frameworks data"""
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
    
    def extract_repo_info(self, github_url: str) -> Tuple[str, str]:
        """Extract owner and repo name from GitHub URL"""
        parsed_url = urlparse(github_url)
        path_parts = parsed_url.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            raise ValueError("Invalid GitHub URL format. Expected format: https://github.com/owner/repo")
        
        return path_parts[0], path_parts[1]

    def get_repo_language(self, owner: str, repo: str) -> Tuple[Optional[str], bool, bool]:
        """Get and validate repository language using API and Bogiefile"""
        tool_language_map = {
            # Java/Scala/Kotlin ecosystem
            'maven': 'java',
            'gradle': 'java',
            'spring': 'java',
            'sbt': 'java',
            'mill': 'java',
            'kotlinc': 'java',
            'kotlin': 'java',
            'scala': 'java',
            
            # JavaScript ecosystem
            'npm': 'javascript',
            'npm-bundle': 'javascript',
            'yarn': 'javascript',
            'yarn-bundle': 'javascript',
            'node': 'javascript',
            
            # Python ecosystem
            'python': 'python',
            'pip': 'python',
            'poetry': 'python',
            
            # .NET ecosystem
            'dotnet': 'dotnet',
            'nuget': 'dotnet',
            'csharp': 'dotnet',
            
            # Go ecosystem
            'go': 'go',
            'golang': 'go'
        }

        try:
            # First try GitHub API
            api_url = f"{self.api_base_url}/repos/{owner}/{repo}"
            response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code != 200:
                print(f"Error getting repository info: {response.status_code}")
                print(f"Response: {response.text}")
                return None, False, False

            repo_data = response.json()
            api_language = repo_data.get("language", "").lower()
            archived = repo_data.get("archived", False)

            # If API language is in primary languages, use it
            if api_language in self.PRIMARY_LANGUAGES:
                print(f"Using API-detected language: {api_language}")
                return api_language, archived, True

            # If API language is not in primary languages, check Bogiefile
            print(f"API language '{api_language}' not in primary languages, checking Bogiefile...")
            bogiefile_content = self.download_file(owner, repo, "Bogiefile")
            
            if bogiefile_content:
                tool_matches = self.dependency_patterns['bogiefile_tool'].finditer(bogiefile_content)
                detected_languages = set()
                
                for match in tool_matches:
                    tool = match.group(1).lower().strip()
                    if tool in tool_language_map:
                        detected_language = tool_language_map[tool]
                        detected_languages.add(detected_language)
                        if detected_language in self.PRIMARY_LANGUAGES:
                            print(f"Mapped Bogiefile tool '{tool}' to language: {detected_language}")
                            return detected_language, archived, True
                
                if detected_languages:
                    # If multiple languages detected, choose based on priority
                    for lang in self.PRIMARY_LANGUAGES:
                        if lang in detected_languages:
                            print(f"Selected primary language '{lang}' from multiple detected: {detected_languages}")
                            return lang, archived, True
                
                print("No supported tools found in Bogiefile")
            
            return api_language if api_language else None, archived, True

        except Exception as e:
            print(f"Error in get_repo_language: {e}")
            return None, False, False
        
    def download_file(self, owner: str, repo: str, file_path: str) -> Optional[str]:
        """Download a specific file from the repository"""
        api_url = f"{self.api_base_url}/repos/{owner}/{repo}/contents/{file_path}"
        
        try:
            response = requests.get(api_url, headers=self.headers, timeout=10)
            if response.status_code != 200:
                return None
            
            content_data = response.json()
            if "content" in content_data:
                import base64
                return base64.b64decode(content_data["content"]).decode('utf-8', errors='replace')
            return None
        except Exception:
            return None

    def search_code_for_patterns(self, owner: str, repo: str, language: str) -> Dict:
        """Search repository code for monitoring and logging framework patterns"""
        results = {
            'has_newrelic': False,
            'has_micrometer': False,
            'has_prometheus': False,
            'has_aws_lambda_powertools': False,
            'logging_frameworks': [],
            'monitoring_frameworks': []
        }
        
        lang = language.lower() if language else None
        if lang not in self.logging_frameworks:
            return results
        
        frameworks = self.logging_frameworks[lang]
        
        try:
            # Search for monitoring frameworks
            for framework in frameworks.get('monitoring', []):
                query = f"{framework} repo:{owner}/{repo}"
                url = f"{self.api_base_url}/search/code?q={query}"
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200 and response.json().get('total_count', 0) > 0:
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
            
            # Search for logging frameworks
            for framework in frameworks.get('logging', []):
                query = f"{framework} repo:{owner}/{repo}"
                url = f"{self.api_base_url}/search/code?q={query}"
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200 and response.json().get('total_count', 0) > 0:
                    results['logging_frameworks'].append(framework)
            
            return results
        
        except Exception as e:
            print(f"Error searching code in {owner}/{repo}: {e}")
            return results

    def check_custom_metrics(self, owner: str, repo: str, language: str) -> Dict:
        """Check if repository uses custom metrics or spans"""
        language_lower = language.lower() if language else ""
        
        if language_lower in ["java", "scala", "kotlin"]:
            return self._check_java_custom_metrics(owner, repo)
        elif language_lower in ["javascript", "typescript", "nodejs", "node"]:
            return self._check_nodejs_custom_metrics(owner, repo)
        elif language_lower == "python":
            return self._check_python_custom_metrics(owner, repo)
        elif language_lower == "go":
            return {"has_custom_metrics": False, "reason": "Golang typically requires manual instrumentation"}
        
        return {"has_custom_metrics": False, "reason": "Language not analyzed for custom metrics"}
    
    def _check_java_custom_metrics(self, owner: str, repo: str) -> Dict:
        """Check Java repositories for Micrometer or New Relic libraries and config files"""
        result = {
            "micrometer": False,
            "newrelic": False,
            "telemetry_sdk": False,
            "config_files": [],
            "patterns_found": []
        }

        # Check dependency files
        build_files = ["pom.xml", "build.gradle", "build.gradle.kts"]
        dependency_patterns = {
            "micrometer": re.compile(r'(?:<groupId>io\.micrometer</groupId>|implementation [\'"]io\.micrometer)'),
            "newrelic": re.compile(r'(?:<groupId>com\.newrelic</groupId>|implementation [\'"]com\.newrelic)'),
            "telemetry": re.compile(r'telemetry')
        }

        for file_name in build_files:
            content = self.download_file(owner, repo, file_name)
            if content:
                if dependency_patterns["micrometer"].search(content):
                    result["micrometer"] = True
                if dependency_patterns["newrelic"].search(content):
                    if dependency_patterns["telemetry"].search(content):
                        result["telemetry_sdk"] = True
                    else:
                        result["newrelic"] = True

        # Search all files in the repository
        try:
            # Get all files in repo
            api_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/main?recursive=1"
            response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code == 404:  # Try master branch if main not found
                api_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/master?recursive=1"
                response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                tree_data = response.json()
                
                # Get all Java files and config files
                all_files = [item['path'] for item in tree_data.get('tree', [])]
                java_files = [f for f in all_files if f.endswith(('.java', '.kt', '.scala'))]
                config_files = [f for f in all_files if f.endswith(('.xml', '.properties', '.yml', '.yaml'))]
                
                # Check config files
                for config_file in config_files:
                    content = self.download_file(owner, repo, config_file)
                    if content and "newrelic" in content.lower():
                        result["config_files"].append(config_file)
                        result["newrelic"] = True
                
                # Patterns to check in source files
                patterns_to_check = [
                    # New Relic patterns
                    (re.compile(r'import\s+com\.newrelic\.telemetry\.'), "New Relic telemetry import"),
                    (re.compile(r'import\s+com\.newrelic\.telemetry\.metrics\.'), "New Relic metrics import"),
                    (re.compile(r'new\s+TelemetryClient\('), "TelemetryClient usage"),
                    (re.compile(r'new\s+MetricBuffer\('), "MetricBuffer usage"),
                    
                    # Micrometer patterns
                    (re.compile(r'import\s+io\.micrometer\.core\.'), "Micrometer core import"),
                    (re.compile(r'@Timed'), "Micrometer @Timed annotation"),
                    (re.compile(r'MeterRegistry'), "MeterRegistry usage"),
                    (re.compile(r'Timer\.(builder|start|record)'), "Timer usage"),
                    (re.compile(r'Counter\.(builder|increment)'), "Counter usage"),
                    (re.compile(r'Gauge\.(builder|create)'), "Gauge usage"),
                    
                    # Additional metric patterns
                    (re.compile(r'MetricRegistry'), "Metric Registry usage"),
                    (re.compile(r'registerMetric'), "Metric registration"),
                    (re.compile(r'recordMetric'), "Metric recording")
                ]

                # Check all Java files
                for file_path in java_files:
                    content = self.download_file(owner, repo, file_path)
                    if content:
                        for pattern, pattern_name in patterns_to_check:
                            if pattern.search(content):
                                if "micrometer" in pattern_name.lower():
                                    result["micrometer"] = True
                                elif "newrelic" in pattern_name.lower():
                                    if "telemetry" in pattern_name.lower():
                                        result["telemetry_sdk"] = True
                                    else:
                                        result["newrelic"] = True
                                result["patterns_found"].append(f"{pattern_name} in {file_path}")
        
        except Exception as e:
            print(f"Error searching Java files: {e}")

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
        
    def _check_nodejs_custom_metrics(self, owner: str, repo: str) -> Dict:
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

        # Search all JS/TS files in the repository
        try:
            # Get all files in repo
            api_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/main?recursive=1"
            response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code == 404:  # Try master branch if main not found
                api_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/master?recursive=1"
                response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                tree_data = response.json()
                js_files = [item['path'] for item in tree_data.get('tree', []) 
                        if item['path'].endswith(('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'))]
                
                patterns_to_check = [
                    (re.compile(r'new CountMetric\('), "CountMetric usage"),
                    (re.compile(r'new GaugeMetric\('), "GaugeMetric usage"),
                    (re.compile(r'new SummaryMetric\('), "SummaryMetric usage"),
                    (re.compile(r'MetricBatchSender'), "MetricBatchSender usage"),
                    (re.compile(r'(import|require)\s*\(?[\'"]newrelic[\'"]\)?'), "newrelic import"),
                    (re.compile(r'(import|require)\s*\(?[\'"]@newrelic/telemetry-sdk[\'"]\)?'), "telemetry-sdk import"),
                    (re.compile(r'const\s+newrelic\s*=\s*require\([\'"]newrelic[\'"]\)'), "newrelic require"),
                    (re.compile(r'import\s*.*\s*from\s*[\'"]newrelic[\'"]\s*'), "newrelic ES6 import"),
                    (re.compile(r'recordMetric\('), "recordMetric usage"),
                    (re.compile(r'createMetric\('), "createMetric usage"),
                    (re.compile(r'newrelic\.addCustomAttribute'), "custom attribute usage")
                ]

                for file_path in js_files:
                    content = self.download_file(owner, repo, file_path)
                    if content:
                        for pattern, pattern_name in patterns_to_check:
                            if pattern.search(content):
                                if "telemetry" in pattern_name.lower():
                                    result["telemetry_sdk"] = True
                                else:
                                    result["newrelic"] = True
                                result["patterns_found"].append(f"{pattern_name} in {file_path}")
        
        except Exception as e:
            print(f"Error searching JavaScript/TypeScript files: {e}")

        return {
            "has_custom_metrics": result["newrelic"] or result["telemetry_sdk"],
            "libraries": {
                "newrelic": result["newrelic"],
                "@newrelic/telemetry-sdk": result["telemetry_sdk"]
            },
            "patterns_found": result["patterns_found"],
            "reason": "New Relic detected" if (result["newrelic"] or result["telemetry_sdk"]) else "No custom metrics libraries detected"
        }
    
    def _check_python_custom_metrics(self, owner: str, repo: str) -> Dict:
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
            lib_pattern = re.compile(re.escape(lib))
            
            for file_name in dependency_files:
                content = self.download_file(owner, repo, file_name)
                if content and lib_pattern.search(content):
                    result["newrelic"] = True if "newrelic" in lib else result["newrelic"]
                    result["newrelic_telemetry_sdk"] = True if "telemetry" in lib else result["newrelic_telemetry_sdk"]
                    break

        # Search all Python files in the repository
        try:
            # Get all files in repo
            api_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/main?recursive=1"
            response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code == 404:  # Try master branch if main not found
                api_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/master?recursive=1"
                response = requests.get(api_url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                tree_data = response.json()
                python_files = [item['path'] for item in tree_data.get('tree', []) 
                            if item['path'].endswith('.py')]
                
                patterns_to_check = [
                    (re.compile(r'from newrelic_telemetry_sdk import'), "newrelic_telemetry_sdk import"),
                    (re.compile(r'import newrelic_telemetry_sdk'), "newrelic_telemetry_sdk import"),
                    (re.compile(r'GaugeMetric\('), "GaugeMetric usage"),
                    (re.compile(r'CountMetric\('), "CountMetric usage"),
                    (re.compile(r'SummaryMetric\('), "SummaryMetric usage"),
                    (re.compile(r'MetricClient\('), "MetricClient usage")
                ]

                for file_path in python_files:
                    content = self.download_file(owner, repo, file_path)
                    if content:
                        for pattern, pattern_name in patterns_to_check:
                            if pattern.search(content):
                                result["newrelic_telemetry_sdk"] = True
                                result["patterns_found"].append(f"{pattern_name} in {file_path}")
        
        except Exception as e:
            print(f"Error searching Python files: {e}")

        return {
            "has_custom_metrics": result["newrelic"] or result["newrelic_telemetry_sdk"],
            "libraries": {
                "newrelic": result["newrelic"],
                "newrelic_telemetry_sdk": result["newrelic_telemetry_sdk"]
            },
            "patterns_found": result["patterns_found"],
            "reason": "New Relic detected" if (result["newrelic"] or result["newrelic_telemetry_sdk"]) else "No custom metrics libraries detected"
        }
    
    def check_auto_instrumentation(self, owner: str, repo: str, language: str) -> Dict:
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
        
    def _check_java_auto_instrumentation(self, owner: str, repo: str) -> Dict:
        """Check Java repositories for auto-instrumentation compatibility"""
        build_files = self._find_java_build_files(owner, repo)
        dependencies, _ = self._extract_java_dependencies(build_files)
        
        detected_frameworks = []
        
        for dep in dependencies:
            full_name = f"{dep['groupId']}:{dep['artifactId']}".lower()
            
            for framework in self.frameworks['java']["libraries"]:
                keywords = framework.lower().split()
                if any(kw in full_name for kw in keywords):
                    detected_frameworks.append({
                        "framework": framework,
                        "groupId": dep["groupId"],
                        "artifactId": dep["artifactId"],
                        "version": dep["version"]
                    })
            
            for server in self.frameworks['java']["app_servers"]:
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

    def _find_java_build_files(self, owner: str, repo: str) -> List[Tuple[str, str]]:
        """Find Java build files in the repository"""
        build_files = []
        target_files = ["pom.xml", "build.gradle", "build.gradle.kts"]
        
        for file in target_files:
            content = self.download_file(owner, repo, file)
            if content:
                build_files.append((file, content))
        
        return build_files

    def _extract_java_dependencies(self, build_files: List[Tuple[str, str]]) -> Tuple[List[Dict], Optional[Dict]]:
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
    
    def _analyze_pom_xml(self, content: str) -> Tuple[List[Dict], Optional[Dict]]:
        """Analyze Maven POM file for dependencies"""
        dependencies = []
        parent_info = None
        
        try:
            wrapped_content = f"<root>{content}</root>"
            root = ET.fromstring(wrapped_content)
            
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
            matches = self.dependency_patterns['maven'].findall(content)
            for match in matches:
                group_id, artifact_id, version = match
                dependencies.append({
                    "groupId": group_id,
                    "artifactId": artifact_id,
                    "version": version if version else "unknown"
                })
            
            parent_match = self.dependency_patterns['parent'].search(content)
            if parent_match:
                parent_info = {
                    "groupId": parent_match.group(1),
                    "artifactId": parent_match.group(2),
                    "version": parent_match.group(3)
                }
                
        return dependencies, parent_info

    def _analyze_gradle_file(self, content: str) -> List[Dict]:
        """Analyze Gradle build file for dependencies"""
        dependencies = []
        
        for pattern in self.dependency_patterns['gradle']:
            matches = pattern.findall(content)
            for match in matches:
                if len(match) == 3:
                    group_id, artifact_id, version = match
                    dependencies.append({
                        "groupId": group_id,
                        "artifactId": artifact_id,
                        "version": version
                    })
        
        return dependencies

    def _check_nodejs_auto_instrumentation(self, owner: str, repo: str) -> Dict:
        """Check Node.js repositories for auto-instrumentation compatibility"""
        frameworks_used = self._find_nodejs_frameworks(owner, repo)
        supported_frameworks = self._match_nodejs_frameworks(frameworks_used)
        
        return {
            "compatible": len(supported_frameworks) > 0,
            "reason": "Supported frameworks detected" if supported_frameworks else "No supported frameworks detected",
            "frameworks": supported_frameworks
        }
    
    def _find_nodejs_frameworks(self, owner: str, repo: str) -> List[Dict]:
        """Find Node.js frameworks used in the repository"""
        frameworks_used = []
        
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
        
        entry_files = ["index.js", "app.js", "server.js", "main.js"]
        for file_path in entry_files:
            content = self.download_file(owner, repo, file_path)
            if content:
                imports = re.findall(r'(?:import\s+.*\s+from\s+|require\()[\'"]([^\'"]*)[\'"]', content)
                for import_path in imports:
                    package_name = import_path.split('/')[0]
                    frameworks_used.append({
                        "name": package_name,
                        "source": file_path,
                        "type": "import"
                    })
        
        return frameworks_used

    def _match_nodejs_frameworks(self, frameworks_used: List[Dict]) -> List[Dict]:
        """Match used Node.js frameworks against supported ones"""
        supported_frameworks = []
        
        for framework in frameworks_used:
            framework_name = framework["name"].lower()
            
            for otel_framework, aliases in self.frameworks['node']["aliases"].items():
                if any(alias in framework_name for alias in aliases):
                    supported_frameworks.append({
                        "framework": otel_framework,
                        "package": framework["name"],
                        "version": framework.get("version", "unknown"),
                        "type": framework.get("type", "unknown")
                    })
                    break
            
            for raw_framework in self.frameworks['node']["raw_frameworks"]:
                if raw_framework in framework_name:
                    if not any(sf["framework"] == raw_framework for sf in supported_frameworks):
                        supported_frameworks.append({
                            "framework": raw_framework,
                            "package": framework["name"],
                            "version": framework.get("version", "unknown"),
                            "type": framework.get("type", "unknown")
                        })
        
        return supported_frameworks

    def _check_python_auto_instrumentation(self, owner: str, repo: str) -> Dict:
        """Check Python repositories for auto-instrumentation compatibility"""
        frameworks_used, files_analyzed = self._find_python_frameworks(owner, repo)
        supported_frameworks = self._match_python_frameworks(frameworks_used)
        
        return {
            "compatible": len(supported_frameworks) > 0,
            "reason": "Supported frameworks detected" if supported_frameworks else "No supported frameworks detected",
            "frameworks": supported_frameworks,
            "files_analyzed": files_analyzed
        }

    def _find_python_frameworks(self, owner: str, repo: str) -> Tuple[List[Dict], List[str]]:
        """Find Python frameworks used in the repository"""
        frameworks_used = []
        files_analyzed = []
        
        req_content = self.download_file(owner, repo, "requirements.txt")
        if req_content:
            files_analyzed.append("requirements.txt")
            frameworks_used.extend(self._analyze_python_package_file(req_content))
        
        pipfile_content = self.download_file(owner, repo, "Pipfile")
        if pipfile_content:
            files_analyzed.append("Pipfile")
            frameworks_used.extend(self._analyze_python_package_file(pipfile_content))
        
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

    def _analyze_python_package_file(self, content: str) -> List[Dict]:
        """Analyze Python package files for dependencies"""
        dependencies = []
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '-r', '--')):
                continue
            
            package = re.split(r'[<=>!~]', line)[0].strip()
            package = re.sub(r'\[.*\]', '', package)
            
            if package:
                dependencies.append({
                    "name": package,
                    "type": "dependency"
                })
        
        return dependencies
    
    def _analyze_python_imports(self, content: str, file_path: str) -> List[Dict]:
        """Analyze Python files for import statements"""
        frameworks_used = []
        
        imports = self.dependency_patterns['import'].findall(content)
        
        for import_path in imports:
            package_name = import_path.split('.')[0]
            frameworks_used.append({
                "name": package_name,
                "source": file_path,
                "type": "import"
            })
        
        return frameworks_used

    def _match_python_frameworks(self, frameworks_used: List[Dict]) -> List[Dict]:
        """Match used Python frameworks against supported ones"""
        supported_frameworks = []
        
        for framework in frameworks_used:
            framework_name = framework["name"].lower()
            
            for otel_framework, aliases in self.frameworks['python']["aliases"].items():
                if any(alias.lower() == framework_name for alias in aliases):
                    supported_frameworks.append({
                        "framework": otel_framework,
                        "package": framework["name"],
                        "type": framework.get("type", "unknown")
                    })
                    break
            
            for raw_framework in self.frameworks['python']["raw_frameworks"]:
                if raw_framework.lower() == framework_name:
                    if not any(sf["framework"] == raw_framework for sf in supported_frameworks):
                        supported_frameworks.append({
                            "framework": raw_framework,
                            "package": framework["name"],
                            "type": framework.get("type", "unknown")
                        })
        
        return supported_frameworks
    
    def analyze_repository(self, github_url: str) -> AnalysisResult:
        """Main analysis function with enhanced logic for manual case detection and recommendations"""
        result = AnalysisResult(repository=github_url)
        
        try:
            owner, repo = self.extract_repo_info(github_url)
            print(f"\nAnalyzing repository: {owner}/{repo}")
            result.repository = f"{owner}/{repo}"
            
            # Step 1: Identify language
            language, archived, repo_accessible = self.get_repo_language(owner, repo)
            result.language = language
            result.archived = archived
            result.repo_accessible = repo_accessible
            print(f"Primary language: {language if language else 'Unknown'}")

            # Step 2: Check language support for auto-instrumentation
            if not language or language.lower() not in self.SUPPORTED_LANGUAGES:
                result.MANUAL_CASE = True
                result.reason.append("Language not supported by auto-instrumentation")
                result.is_golang = language and language.lower() == "go"

            # Step 3: Search for monitoring/logging frameworks
            if language:
                framework_results = self.search_code_for_patterns(owner, repo, language)
                result.has_newrelic = framework_results['has_newrelic']
                result.has_micrometer = framework_results['has_micrometer']
                result.has_prometheus = framework_results['has_prometheus']
                result.has_aws_lambda_powertools = framework_results['has_aws_lambda_powertools']
                result.logging_frameworks = framework_results['logging_frameworks']
                result.monitoring_frameworks = framework_results['monitoring_frameworks']

            # Step 4: Check for custom metrics/spans
            if language:
                custom_metrics_result = self.check_custom_metrics(owner, repo, language)
                result.custom_metrics = custom_metrics_result["has_custom_metrics"]
                result.details["custom_metrics"] = custom_metrics_result
                
                if result.custom_metrics:
                    result.MANUAL_CASE = True
                    result.reason.append("Has custom metrics")

            # Step 5: Check for auto-instrumentation compatibility
            if language:
                auto_instrumentation_result = self.check_auto_instrumentation(owner, repo, language)
                result.auto_instrumentation = auto_instrumentation_result["compatible"]
                result.details["auto_instrumentation"] = auto_instrumentation_result
                
                if not result.auto_instrumentation:
                    result.MANUAL_CASE = True
                    result.reason.append("Framework not supported by auto-instrumentation")

            # Step 6: Check Bogiefile for OTEL indicators and flavor
            bogiefile_content = self.download_file(owner, repo, "Bogiefile")
            if bogiefile_content:
                try:
                    # Split content into lines and ignore comments
                    lines = [line.strip() for line in bogiefile_content.split('\n') 
                            if line.strip() and not line.strip().startswith('#')]
                    cleaned_content = '\n'.join(lines)
                    
                    # Search in cleaned content (without comments)
                    flavor_match = self.dependency_patterns['flavor'].search(cleaned_content)
                    if flavor_match:
                        result.flavor = flavor_match.group(1).strip()
                        result.supported = result.flavor in self.SUPPORTED_FLAVORS
                    else:
                        result.supported = False
                    
                    if self.dependency_patterns['otel_indicator'].search(cleaned_content):
                        result.OTEL_Onboarded = True
                except Exception as e:
                    print(f"Error parsing Bogiefile: {e}")
                    result.supported = False

            # Step 7: Determine final recommendation
            if result.MANUAL_CASE:
                if result.OTEL_Onboarded:
                    result.recommendation = "No Action needed, already onboarded"
                    result.reason.append("Already onboarded")
                else:
                    result.recommendation = "Use Windsurf"
                    if not result.reason:
                        result.reason.append("Manual instrumentation required")
            else:
                if result.OTEL_Onboarded:
                    result.recommendation = "No Action needed, already onboarded"
                    result.reason = ["Already onboarded"]
                else:
                    result.recommendation = "Use OpenTelemetry auto-instrumentation"
                    result.reason = ["Compatible with auto-instrumentation"]
                    if language and language.lower() == "python":
                        frameworks = result.details["auto_instrumentation"].get("frameworks", [])
                        result.reason[0] += f" (Detected: {', '.join(fw['framework'] for fw in frameworks)})"

            # Combine all reasons into a single string
            result.reason = " and ".join(result.reason)
            
            return result

        except Exception as e:
            print(f"Error in analyze_repository: {e}")
            result.error = str(e)
            result.repo_accessible = False
            result.recommendation = "Cannot analyze - Invalid repository URL or access error"
            result.reason = f"Error: {str(e)}"
            return result


def process_csv(input_file: str, output_file: Optional[str] = None) -> None:
    """Process CSV with additional fields from m2_new.py"""
    if output_file is None:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_analyzed{ext}"
    
    analyzer = GitHubRepoAnalyzer()
    
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile, \
         open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        
        reader = csv.DictReader(infile)
        
        fieldnames = reader.fieldnames + [
            'Primary_Language',
            'Repo_Accessible',
            'Archived',
            'OTEL_Onboarded',
            'Manual_Case',
            'Auto_Instrumentation_Compatible',
            'Custom_Metrics_Detected',
            'Recommendation',
            'Reason',
            'Flavor',
            'Supported_Flavor',
            'Has_NewRelic',
            'Has_Micrometer',
            'Has_Prometheus',
            'Has_AWS_Lambda_Powertools',
            'Logging_Frameworks'
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
            
            row.update({
                'Primary_Language': result.language or '',
                'Repo_Accessible': 'TRUE' if result.repo_accessible else 'FALSE',
                'Archived': 'TRUE' if result.archived else 'FALSE',
                'OTEL_Onboarded': 'TRUE' if result.OTEL_Onboarded else 'FALSE',
                'Manual_Case': 'TRUE' if result.MANUAL_CASE else 'FALSE',
                'Auto_Instrumentation_Compatible': 'TRUE' if result.auto_instrumentation else 'FALSE',
                'Custom_Metrics_Detected': 'TRUE' if result.custom_metrics else 'FALSE',
                'Recommendation': result.recommendation or '',
                'Reason': result.reason or '',
                'Flavor': result.flavor or '',
                'Supported_Flavor': 'TRUE' if result.supported else 'FALSE',
                'Has_NewRelic': 'TRUE' if result.has_newrelic else 'FALSE',
                'Has_Micrometer': 'TRUE' if result.has_micrometer else 'FALSE',
                'Has_Prometheus': 'TRUE' if result.has_prometheus else 'FALSE',
                'Has_AWS_Lambda_Powertools': 'TRUE' if result.has_aws_lambda_powertools else 'FALSE',
                'Logging_Frameworks': ', '.join(result.logging_frameworks) if result.logging_frameworks else ''
            })
            
            writer.writerow(row)
    
    print(f"\nAnalysis complete. Results saved to: {output_file}")


def analyze_repo_wrapper(analyzer: GitHubRepoAnalyzer, url: str) -> AnalysisResult:
    """Wrapper function for parallel processing"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        return analyzer.analyze_repository(url)
    except Exception as e:
        return AnalysisResult(repository=url, error=str(e))


def process_chunk(args: Tuple[GitHubRepoAnalyzer, List[Tuple[str, Dict]]]) -> List[Dict]:
    """Process a chunk of repositories"""
    analyzer, chunk = args
    results = []
    
    for url, original_row in chunk:
        analysis = analyze_repo_wrapper(analyzer, url)
        results.append({
            'original_row': original_row,
            'analysis': analysis
        })
    
    return results


def parallel_process_csv(input_file: str, output_file: Optional[str] = None, max_workers: int = 100) -> None:
    """Process CSV in parallel with multiple workers"""
    if output_file is None:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_analyzed_parallel{ext}"
    
    # Read URLs from CSV
    urls = []
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            github_url = row.get('url') or row.get('github_url') or row.get('repository_url')
            if github_url:
                urls.append((github_url, row))

    total_count = len(urls)
    print(f"Found {total_count} repositories to analyze")
    
    # Ensure max_workers is at least 1
    max_workers = max(1, min(max_workers, 100))  # Keep between 1 and 100
    
    # Calculate chunk size - improved version
    chunk_size = max(10, total_count // (max_workers * 5))
    
    # Split into chunks
    url_chunks = [urls[i:i + chunk_size] for i in range(0, total_count, chunk_size)]
    
    # Create analyzer instances
    analyzers = [GitHubRepoAnalyzer() for _ in range(min(max_workers, len(url_chunks)))]
    
    print(f"Starting parallel processing with {len(analyzers)} workers...")
    start_time = time.time()
    
    # Process in parallel
    with Pool(len(analyzers)) as pool:
        results = []
        completed = 0
        
        # Process chunks asynchronously
        for result in pool.imap_unordered(
            process_chunk,
            [(analyzer, chunk) for analyzer, chunk in zip(analyzers, url_chunks)]
        ):
            results.extend(result)
            completed += len(result)
            print(f"Processed {completed}/{total_count} repos ({completed/total_count*100:.1f}%)")
    
    # Write results to CSV
    with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        if not results:
            print("No results to write")
            return
            
        fieldnames = list(results[0]['original_row'].keys()) + [
            'Primary_Language',
            'Repo_Accessible',
            'Archived',
            'OTEL_Onboarded',
            'Manual_Case',
            'Auto_Instrumentation_Compatible',
            'Custom_Metrics_Detected',
            'Recommendation',
            'Reason',
            'Flavor',
            'Supported_Flavor',
            'Has_NewRelic',
            'Has_Micrometer',
            'Has_Prometheus',
            'Has_AWS_Lambda_Powertools',
            'Logging_Frameworks'
        ]
        
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            row = result['original_row'].copy()
            analysis = result['analysis']
            
            row.update({
                'Primary_Language': analysis.language or '',
                'Repo_Accessible': 'TRUE' if analysis.repo_accessible else 'FALSE',
                'Archived': 'TRUE' if analysis.archived else 'FALSE',
                'OTEL_Onboarded': 'TRUE' if analysis.OTEL_Onboarded else 'FALSE',
                'Manual_Case': 'TRUE' if analysis.MANUAL_CASE else 'FALSE',
                'Auto_Instrumentation_Compatible': 'TRUE' if analysis.auto_instrumentation else 'FALSE',
                'Custom_Metrics_Detected': 'TRUE' if analysis.custom_metrics else 'FALSE',
                'Recommendation': analysis.recommendation or '',
                'Reason': analysis.reason or '',
                'Flavor': analysis.flavor or '',
                'Supported_Flavor': 'TRUE' if analysis.supported else 'FALSE',
                'Has_NewRelic': 'TRUE' if analysis.has_newrelic else 'FALSE',
                'Has_Micrometer': 'TRUE' if analysis.has_micrometer else 'FALSE',
                'Has_Prometheus': 'TRUE' if analysis.has_prometheus else 'FALSE',
                'Has_AWS_Lambda_Powertools': 'TRUE' if analysis.has_aws_lambda_powertools else 'FALSE',
                'Logging_Frameworks': ', '.join(analysis.logging_frameworks) if analysis.logging_frameworks else ''
            })
            
            writer.writerow(row)
    
    elapsed_time = time.time() - start_time
    print(f"\nAnalysis complete. Processed {total_count} repositories in {elapsed_time:.1f} seconds")
    print(f"Results saved to: {output_file}")
    print(f"Average speed: {total_count/elapsed_time:.1f} repos/sec")
    
#############################################################
# LOGGING CONFIGURATION
#############################################################

def configure_logging(debug_mode: bool = False) -> None:
    """Configure logging based on execution environment and debug mode.
    
    Args:
        debug_mode: If True, sets log level to DEBUG. Otherwise, uses INFO.
    """
    log_level = logging.DEBUG if debug_mode else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if EXECUTED_IN_CODEGENIE:
        log_path = f"/app/logs/{os.environ.get('HOSTNAME')}_logs/app.log"
        logging.basicConfig(
            filename=log_path,
            level=log_level,
            format=log_format
        )
        logging.info(f"Configured logging for CodeGenie environment at {log_path}")
    else:
        logging.basicConfig(
            level=log_level,
            format=log_format
        )
        logging.info("Running in local mode with console logging")



#############################################################
# UTILITY FUNCTIONS
#############################################################

def detect_repository_language(repository_path: str) -> str:
    """Identifies the primary programming language of a given repository.
    
    Args:
        repository_path: Path to the repository directory
        
    Returns:
        Detected language ('java', 'python', 'nodejs', or 'unknown')
    """
    
    java_files = ['.java', 'pom.xml', 'build.gradle']
    python_files = ['.py', 'requirements.txt', 'Pipfile', 'pyproject.toml']
    go_files = ['.go', 'go.mod', 'Gopkg.toml']
    nodejs_files = ['.js', '.ts', 'package.json', 'yarn.lock']

    java_count = python_count = go_count = nodejs_count = 0
    
    for root, _, files in os.walk(repository_path):
        for file in files:
            file_lower = file.lower()
            if any(file_lower.endswith(ext.lower()) for ext in java_files):
                java_count += 1
            elif any(file_lower.endswith(ext.lower()) for ext in python_files):
                python_count += 1
            elif any(file_lower.endswith(ext.lower()) for ext in go_files):
                go_count += 1
            elif any(file_lower.endswith(ext.lower()) for ext in nodejs_files):
                nodejs_count += 1
    
    language_map = {
        'java': java_count,
        'python': python_count,
        'go': go_count,
        'nodejs': nodejs_count
    }
    
    detected_language = max(language_map.items(), key=lambda x: x[1])[0]
    if language_map[detected_language] == 0:
        detected_language = 'unknown'
    
    logging.info(f"Detected language: {detected_language}")
    return detected_language

def find_file_in_repository(repository_path: str, file_name: str) -> Optional[str]:
    """Searches for a file in the repository and returns its path if found.
    
    Args:
        repository_path: Path to the repository directory to search in
        file_name: Name of the file to search for
        
    Returns:
        Absolute path to the file if found, None otherwise
    """
    for root, _, files in os.walk(repository_path):
        if file_name in files:
            file_path = os.path.join(root, file_name)
            logging.info(f"File '{file_name}' found in repository: {file_path}")
            return file_path
    logging.info(f"File '{file_name}' not found in repository: {repository_path}")
    return None

def does_file_contain_string(repo_path: str, file_name: str, search_string: str) -> bool:
    """Checks if a file contains a specific string (case-insensitive, ignoring comments).
    
    Args:
        repo_path: Path to the repository directory
        file_name: Name of the file to search in
        search_string: String to search for
        
    Returns:
        True if the file contains the string, False otherwise
    """
    file_path = os.path.join(repo_path, file_name)
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        content = '\n'.join([line.lower() for line in content.split('\n') if not line.strip().startswith('#')])
        return search_string.lower() in content and 'USE_MASH_JAVA_OPTIONS'.lower() not in content
    except FileNotFoundError:
        return False

def does_file_contain_regex(repo_path: str, file_name: str, regex: str) -> bool:
    """Checks if a file contains text matching a regex pattern.
    
    Args:
        repo_path: Path to the repository directory
        file_name: Name of the file to search in
        regex: Regular expression pattern to search for
        
    Returns:
        True if the pattern is found, False otherwise
    """
    file_path = os.path.join(repo_path, file_name)
    try:
        with open(file_path, 'r', encoding="utf-8") as file:
            content = file.read()
        content = '\n'.join([line for line in content.split('\n') if not line.strip().startswith('#')])
        return bool(re.search(regex, content, re.IGNORECASE))
    except Exception as e:
        logging.error(f"Error reading file at {file_path}: {e}")
        return False
    
def read_file(filepath: str) -> str:
    """Reads and returns the content of a file.
    
    Args:
        filepath: Path to the file to read
        
    Returns:
        Content of the file as a string
    """
    with open(filepath, 'r') as file:
        return file.read()

def read_top_level_comments(file_path: str) -> str:
    """Reads and returns top-level comments from a file.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        Top-level comments from the file
    """
    top_level_comments = ''
    top_level_comments_exist = False
    with open(file_path, "r") as file:
        for line in file.readlines():
            top_level_comments = top_level_comments + line
            if line.startswith('---'):
                top_level_comments_exist = True
                break
    return top_level_comments if top_level_comments_exist is True else ''

#############################################################
# YAML PROCESSING FUNCTIONS
#############################################################

def read_yaml_with_empty_lines(dir: str, file_name: str) -> Dict:
    """Reads YAML file while preserving comments and formatting.
    Args:
        dir: Directory containing the YAML file
        file_name: Name of the YAML file
    Returns:
        Parsed YAML content as a dictionary
    """
    file_path = os.path.join(dir, file_name)
    with open(file_path, 'r') as file:
        yaml = ruamel.yaml.YAML()
        yaml.preserve_quotes = True
        yaml.width = 1000
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        yaml.allow_duplicate_keys = True
        return yaml.load(file)

def write_yaml_with_empty_lines(dir: str, file_name: str, data: Dict) -> None:
    """Writes YAML file while preserving comments and formatting.
    
    Args:
        dir: Directory to write the YAML file
        file_name: Name of the YAML file to write
        data: YAML content to write
    """
    file_path = os.path.join(dir, file_name)
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True  
    yaml.indent(mapping=2, sequence=4, offset=2)  
    yaml.default_flow_style = False  
    yaml.allow_duplicate_keys = True  
    with open(file_path, 'w') as file:
        yaml.dump(data, file)
        
def extract_values_case_insensitive(data: Dict, keys: List[str]) -> Dict:
    """Recursively extract values for the given keys in a case-insensitive way.
    
    Args:
        data: The nested YAML data structure to search through
        keys: List of keys to extract values for
        
    Returns:
        Dictionary containing the found keys and their values
    """
    result = {}
    if not data or not isinstance(data, dict):
        return result

    for key, value in data.items():
        key_lower = key.lower() if isinstance(key, str) else str(key).lower()
        
        for search_key in keys:
            if search_key.lower() == key_lower:
                result[search_key] = value

        if isinstance(value, dict):
            nested_result = extract_values_case_insensitive(value, keys)
            result.update(nested_result)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    nested_result = extract_values_case_insensitive(item, keys)
                    result.update(nested_result)

    return result

def delete_keys_matching_pattern(data: Union[Dict, List], pattern: str) -> None:
    """Recursively delete keys matching the given regex pattern while preserving comments.
    
    Args:
        data: The YAML data structure to process
        pattern: Regular expression pattern to match keys against
    """
    if isinstance(data, dict):
        keys_to_delete = [key for key in data.keys() if isinstance(key, str) and re.match(pattern, key, re.IGNORECASE)]
        
        for key in keys_to_delete:
            comment = data.ca.items.get(key, None)
            data.pop(key)
            
            if comment and data:
                last_key = list(data.keys())[-1] 
                data.ca.items[last_key] = data.ca.items.get(last_key, []) + comment

        for key in list(data.keys()):
            delete_keys_matching_pattern(data[key], pattern)

    elif isinstance(data, list):
        for item in data:
            delete_keys_matching_pattern(item, pattern)

def log_and_exit(message: str, log_level: str) -> None:
    """Logs a message at the specified log level and exits the function.
    
    Args:
        message: The message to log
        log_level: The logging level ('debug', 'info', 'warn', 'error')
    """
    log_func = {
        'debug': logging.debug,
        'info': logging.info,
        'warn': logging.warning,
        'error': logging.error
    }.get(log_level.lower(), logging.info)
    
    log_func(message)
    return

def find_deployment_type(root: Dict) -> str:
    """Returns the deployment type from the Bogiefile.
    
    Args:
        root: The parsed Bogiefile YAML data
        
    Returns:
        The gear type (deployment type) from the first environment
    """
    return root['environments'][0]['gear']

def find_allowlisted_gears(gears: List[str], element: Dict) -> List[Dict]:
    """Find all environments from the YAML that match the allowlisted gear patterns.
    
    Args:
        gears: List of gear patterns to match against
        element: The parsed Bogiefile YAML data
        
    Returns:
        List of environment dictionaries that have matching gear types
    """
    filtered_envs = []
    if 'environments' in element:
        for env in element['environments']:
            if any(gear in env['gear'] for gear in gears):
                logging.info(f"Match found: {env['gear']}")
                filtered_envs.append(env)
    return filtered_envs

def contains_key_value_pair(key: str, value: str, root: Dict) -> bool:
    """Checks if the dictionary contains a specific key-value pair.
    
    Args:
        key: The key to search for
        value: The value to match
        root: The dictionary to search in
        
    Returns:
        True if the key-value pair exists, False otherwise
    """
    for _key in root.keys():
        if _key.strip().upper() == key.strip().upper() and root[_key] == value.strip().split(' ')[0]:
            return True
    return False
def contains_key(key: str, element: Dict) -> bool:
    """Checks if the dictionary contains a specific key regardless of its value.
    
    Args:
        key: The key to search for
        element: The dictionary to search in
        
    Returns:
        True if the key exists, False otherwise
    """
    for _key in element.keys():
        if _key.strip().upper() == key.strip().upper():
            return True
    return False

def add_key_value_pair(pos: int, key: str, value: Any, root: Dict, comment: Optional[str] = None) -> None:
    """Adds a new key-value pair (and optional comment) to the element.
    
    Args:
        pos: Position to insert the key-value pair
        key: Key to insert
        value: Value to associate with the key
        root: Dictionary to modify
        comment: Optional comment to add
    """
    try:
        if hasattr(root, 'insert'):
            root.insert(pos, key, value, comment)
        else:
            root[key] = value
    except Exception as e:
        root[key] = value
        logging.warning(f"Using direct assignment for key '{key}' due to: {e}")
        if comment and hasattr(root, 'ca') and hasattr(root.ca, 'items'):
            try:
                root.ca.items[key] = [None, None, None, comment]
            except:
                pass

def update_key_value_pair(key: str, new_value: Any, root: Dict, comment: Optional[str] = None) -> None:
    """Updates a key-value pair (and optional comment) in the element.
    
    Args:
        key: Key to update
        new_value: New value to set
        root: Dictionary to modify
        comment: Optional comment to add
    """
    if comment is not None:
        root[key] = new_value + ' # ' + comment
    else:
        root[key] = new_value

def delete_keys(regex: str, root: Dict) -> bool:
    """Delete keys matching the regex and preserve their comments.
    
    Args:
        regex: Regular expression pattern to match against keys
        root: Dictionary to remove keys from
        
    Returns:
        True if any keys were deleted, False otherwise
    """
    keys_to_pop = [key for key in root if re.match(regex, key, re.IGNORECASE)]
    comments_to_preserve = []
    for key in keys_to_pop:
        comment = root.ca.items.get(key, None)
        if comment and isinstance(comment, list): 
            comments_to_preserve.extend(comment)
        root.pop(key)
    if comments_to_preserve and root:
        last_key = list(root.keys())[-1] 
        root.ca.items[last_key] = root.ca.items.get(last_key, []) + comments_to_preserve
    return len(keys_to_pop) > 0

def build_mandatory_tags(data: Dict) -> Dict:
    """Builds mandatory tags from Bogiefile vars.
    
    Args:
        data: Parsed Bogiefile data
        
    Returns:
        Dictionary of mandatory tags
    """
    return {
        'asv': data['vars']['asv'],
        'ba': data['vars']['ba'],
        'component': data['vars']['component']
    }

def write_standard_file(file_path: str, lines: List[str]) -> None:
    """Writes content to a file.
    
    Args:
        file_path: Path to the file to write
        lines: List of lines to write
    """
    with open(file_path, 'w') as f:
        f.writelines(lines)

def normalize_whitespace(content: str) -> str:
    """Normalizes whitespace in content.
    
    Args:
        content: String content to normalize
        
    Returns:
        Normalized content string
    """
    return '\n'.join(line.rstrip() for line in content.strip().splitlines())

def format_java_opts(java_opts_str: str) -> str:
    """Formats JAVA_OPTS with proper line breaks.
    
    Args:
        java_opts_str: JAVA_OPTS string to format
        
    Returns:
        Formatted JAVA_OPTS string
    """
    opts = []
    current = []
    for part in java_opts_str.split():
        if part.startswith('-'):
            if current:
                opts.append(' '.join(current))
                current = []
            current.append(part)
        else:
            current.append(part)
    if current:
        opts.append(' '.join(current))
    return '\n'.join(opts)

def process_java_opts(obj: Union[Dict, List]) -> None:
    """Processes JAVA_OPTS in YAML data for proper formatting.
    
    Args:
        obj: YAML data structure to process
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == 'JAVA_OPTS' and isinstance(value, str):
                formatted = format_java_opts(value)
                obj[key] = LiteralScalarString(formatted)
            elif isinstance(value, (dict, list)):
                process_java_opts(value)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                process_java_opts(item)

def process_policy(obj: Union[Dict, List]) -> None:
    """Processes policy in YAML data for proper formatting.
    
    Args:
        obj: YAML data structure to process
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == 'policy' and isinstance(value, str):
                try:
                    parsed = json.loads(value)
                    obj[key] = LiteralScalarString(json.dumps(parsed, indent=2))
                except json.JSONDecodeError:
                    pass
            elif isinstance(value, (dict, list)):
                process_policy(value)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                process_policy(item)

def get_runtime(env: Dict) -> Optional[str]:
    """Extracts and validates the runtime version from environment.
    
    Args:
        env: Environment dictionary from Bogiefile
        
    Returns:
        Runtime version string or None if invalid
    """
    runtime = ''
    node_runtimes = ['16', '18', '20', '22']
    java_runtimes = ['11', '17', '21']
    python_runtimes = ['3.8', '3.9', '3.10', '3.11']

    if 'runtime' in env['inputs']:
        runtime = env['inputs']['runtime']
        if 'nodejs' in runtime:
            version = runtime[len('nodejs'):].replace('.x', '')
            if version in node_runtimes:
                return f'nodejs{version}'
        elif 'java' in runtime:
            version = runtime[len('java'):].replace('.x', '')
            if version in java_runtimes:
                return f'java{version}'
        elif 'python' in runtime:
            version = runtime[len('python'):].replace('.x', '')
            if version in python_runtimes:
                return f'python{version}'
    return None

def check_handler(env: Dict) -> None:
    """Checks and updates Python handler format if needed.
    
    Args:
        env: Environment dictionary from Bogiefile
    """
    if 'inputs' in env and 'handler' in env['inputs']:
        handler = env['inputs']['handler']
        if '/' in handler:
            env['inputs']['handler'] = handler.replace('/', '.')

#############################################################
# DOCKER PROCESSING FUNCTIONS
#############################################################

def check_docker_image_type(file_path: str) -> str:
    """Determines the type of Docker image from the Dockerfile.
    
    Args:
        file_path: Path to the Dockerfile
        
    Returns:
        Image type ('distroless', 'apm', 'tomcat', or 'generic')
    """
    content = read_file(file_path)
    for line in content.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith('#'):
            continue
        if 'FROM' in stripped_line:
            if 'distroless' in stripped_line:
                return 'distroless'
            elif APM_SUPPORTED_IMAGE_PREFIX in stripped_line or PLEC_APM_SUPPORTED_IMAGE_PREFIX in stripped_line:
                return 'apm'
            elif TOMCAT_SUPPORTED_IMAGE_PREFIX in stripped_line:
                return 'tomcat'
            else:
                return 'generic'
            
def does_dockerfile_contains_otel_supported_image(file_path: str) -> bool:
    """Checks if Dockerfile contains a supported APM image.
    
    Args:
        file_path: Path to the Dockerfile
        
    Returns:
        True if supported image found, False otherwise
    """
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if not line.strip().startswith('#') and line.strip().startswith("FROM") and (
                APM_SUPPORTED_IMAGE_PREFIX in line or 
                TOMCAT_SUPPORTED_IMAGE_PREFIX in line or 
                PLEC_APM_SUPPORTED_IMAGE_PREFIX in line
            ):
                return True
    return False

def omit_newrelic_vars_from_dockerfile(file_path: str) -> List[str]:
    """Removes NewRelic-related lines from Dockerfile.
    
    Args:
        file_path: Path to the Dockerfile
        
    Returns:
        List of cleaned lines if changes were made, empty list otherwise
    """
    final_lines = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if ('newrelic_' in line.lower() or 'newrelic.' in line.lower() or 'new_relic' in line.lower()) and not line.startswith('#'):
                continue
            final_lines.append(line)
    return final_lines if len(final_lines) < len(lines) else []

def check_prerequisites_and_return_image_type(repository_path: str = '.') -> Optional[str]:
    """Checks repository prerequisites and returns the Docker image type.
    
    Args:
        repository_path: Path to the repository directory
        
    Returns:
        Docker image type if prerequisites met, None otherwise
    """
    if not os.path.isdir(repository_path):
        return None

    repository_language = detect_repository_language(repository_path)

    if find_file_in_repository(repository_path, "Bogiefile") is None:
        return None

    if does_file_contain_string(repository_path, "Bogiefile", "OTEL_ENABLED: true"):
        return None
    
    dockerfile_path = find_file_in_repository(repository_path, "Dockerfile")
    if dockerfile_path:
        return check_docker_image_type(dockerfile_path)
    return None

def upsert_mandatory_tags(pos: int, root: Dict, key: str, tags: Dict) -> bool:
    """Updates or inserts mandatory tags in the given dictionary.
    
    Args:
        pos: Position to insert if needed
        root: Dictionary to update
        key: Key to update
        tags: Dictionary of tags to add
        
    Returns:
        True if updates were made, False otherwise
    """
    resource_attributes = ''
    resources_attributes_updated = False
    is_quoted = False
    if key in root:
        resource_attributes = root[key]
        if resource_attributes != '' and resource_attributes.startswith('"'):
            is_quoted = True
            resource_attributes = resource_attributes.replace('"', '')
    for tag in tags:
        tag_prefix = '' if tag in ['TRACES_TARGET', 'METRICS_TARGET'] else 'tags.'
        search_tag = f'{tag_prefix}{tag.upper()}='
        if search_tag not in resource_attributes.upper():
            resource_attributes = resource_attributes + tag_prefix + tag.upper() + '=' + tags[tag] + ','
            resources_attributes_updated = True
          
        else:
            print(f"Tag {tag} already exists in resource_attributes.")

    if resources_attributes_updated:
        resource_attributes = resource_attributes[:-1]
        if is_quoted:
            resource_attributes = '"' + resource_attributes + '"'
        add_key_value_pair(pos, key, resource_attributes, root)

    return resources_attributes_updated

def process_dockerfile_lines(endpoint: str, asv: str, ba: str, component: str, 
                           write_type: str, file_path: str, 
                           add_java_opts_if_missing: bool = False) -> None:
    """Processes Dockerfile lines for OpenTelemetry instrumentation.
    
    Args:
        endpoint: OTEL endpoint URL
        asv: ASV tag value
        ba: BA tag value
        component: Component tag value
        write_type: Docker image type ('generic' or 'distroless')
        file_path: Path to Dockerfile
        add_java_opts_if_missing: Whether to add JAVA_OPTS if missing
    """
    add_java_agent_install_lines = '''
RUN mkdir -p /app/otel
ARG OTEL_AGENT_VERSION=2.1.0
ARG OTEL_REPO=https://artifactory.cloud.capitalone.com/artifactory/maven-internalfacing/io
ADD --chown=appuser:appuser $OTEL_REPO/opentelemetry/javaagent/opentelemetry-javaagent/$OTEL_AGENT_VERSION/opentelemetry-javaagent-${OTEL_AGENT_VERSION}.jar /app/otel/otel-javaagent.jar
'''
    generic_add_java_opts_lines_docker = f'-javaagent:/app/otel/otel-javaagent.jar -Dotel.service.name=<SERVICE_NAME> -Dotel.resource.attributes=service.instance.id=$HOSTNAME,tags.ASV={asv},tags.BA={ba},tags.COMPONENT={component} '
    
    agent_lines_inserted = False
    with open(file_path, 'r') as f:
        lines = f.readlines()
        new_lines = []

    for line in lines:
        if write_type == 'generic':
            if DOCKER_IMAGE_PATTERN.match(line):
                new_lines.append(line)
                if not agent_lines_inserted:
                    new_lines.append(add_java_agent_install_lines)
                    agent_lines_inserted = True
                    if add_java_opts_if_missing:
                        new_lines.append(f'ENV JAVA_OPTS="{generic_add_java_opts_lines_docker}"\n')
            elif 'newrelic' in line.lower():
                continue
            elif "ENV JAVA_OPTS=" in line:
                line = re.sub(r'ENV JAVA_OPTS="([^"]+)"', r'ENV JAVA_OPTS="{}\1 "'.format(generic_add_java_opts_lines_docker), line)
                new_lines.append(line)
            elif "ENV JAVA_OPTIONS=" in line:
                line = re.sub(r'ENV JAVA_OPTIONS="([^"]+)"', r'ENV JAVA_OPTIONS="{}\1 "'.format(generic_add_java_opts_lines_docker), line)
                new_lines.append(line)
            else:
                new_lines.append(line)

    with open(file_path, 'w') as f:
        for line in new_lines:
            f.write(line)

def process_for_ecs(env: Dict, image_type: str, mandatory_tags: Dict) -> bool:
    """Processes ECS environment for OpenTelemetry instrumentation.
    
    Args:
        env: Environment dictionary from Bogiefile
        image_type: Docker image type
        mandatory_tags: Dictionary of mandatory tags
        
    Returns:
        True if updates were made, False otherwise
    """
    BOGIEFILE_CONTENT_UPDATED = False
    if 'container_env' in env['inputs']:
        container_env = env['inputs']['container_env']

        pos = int(len(container_env.keys())/2)
        endpoint = 'http://172.17.0.1:4317'  

        keys = ['java_opts', 'java_options', 'JAVA_OPTS', 'JAVA_OPTIONS']
        
        if image_type == 'apm':
            if contains_key_value_pair('OTEL_ENABLED', 'true', container_env) is False and contains_key_value_pair('OTEL_ENABLED', 'True', container_env) is False:
                add_key_value_pair(pos, 'OTEL_ENABLED', True, container_env, 'To turn on OTel') # set OTEL_ENABLED to true
                
                if 'SERVICE_NAME' not in container_env:
                    add_key_value_pair(pos+1, 'SERVICE_NAME', '<YOUR SERVICE NAME>',container_env, 'Replace with your desired service name')
                        
                new_pos = int(len(container_env.keys())/2)
                upsert_mandatory_tags(new_pos, container_env, 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags)
                
                if any(re.search(r'new_relic', key, re.IGNORECASE) for key in container_env.keys()):
                    delete_keys('NEW_RELIC', container_env)
                    return True
                else:
                    delete_keys('NEWRELIC', container_env)
                    return True
        
                
            else:
                return upsert_mandatory_tags(pos,container_env, 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags)

        elif (image_type == 'generic' or image_type=='distroless') and (contains_key('JAVA_OPTIONS', container_env) or contains_key('JAVA_OPTS', container_env)):
            if image_type == 'generic':
                construct_java_opts = [
                    '-javaagent:/app/otel/otel-javaagent.jar',
                    '-Dotel.service.name=<SERVICE_NAME>',
                    f'-Dotel.exporter.otlp.endpoint=${endpoint}'
                ]
            elif image_type == 'distroless':
                construct_java_opts = []

            for key in keys:
                if key in container_env:
                    current_value = container_env[key]
                    if isinstance(current_value, list):
                        current_value = ' '.join(current_value)
                    final_java_opts = ' '.join(construct_java_opts) + ' ' + current_value
                    update_key_value_pair(key, final_java_opts, container_env)
                    BOGIEFILE_CONTENT_UPDATED = True
        
        if delete_keys('NEWRELIC', container_env) or upsert_mandatory_tags(pos+1, container_env, 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags):
            BOGIEFILE_CONTENT_UPDATED = True
    
    return BOGIEFILE_CONTENT_UPDATED

def process_for_fargate(env: Dict, image_type: str, mandatory_tags: Dict) -> bool:
    """Processes Fargate environment for OpenTelemetry instrumentation.
    
    Args:
        env: Environment dictionary from Bogiefile
        mandatory_tags: Dictionary of mandatory tags
        
    Returns:
        True if updates were made, False otherwise
    """
    BOGIEFILE_CONTENT_UPDATED = False
    endpoint = 'http://localhost:4317'
    
    if 'service' in env['inputs'] and 'regions' in env:
        for fargate_service in env['inputs']['service']:
            if 'containers' not in fargate_service:
                continue
                
            for fg_container in fargate_service['containers']:
                if 'env' not in fg_container:
                    continue
                    
                fargate_container_env = fg_container['env']
                pos = int(len(fargate_container_env.keys())/2)
                
                if 'application_configuration' in env['inputs'] and 'logging' in env['inputs']['application_configuration']:
                    logging_config = env['inputs']['application_configuration']['logging']
                    if 'otel_collector' not in logging_config:
                        pos = int(len(logging_config.keys()) / 2)
                        add_key_value_pair(pos, 'otel_collector', 'otelservices-<lob>', logging_config, 'Directs the traces to the LOB gateway')
                        BOGIEFILE_CONTENT_UPDATED = True
                
                if 'regions' in env:
                    for region in env['regions']:
                        if 'application_configuration' in region and 'logging' in region['application_configuration']:
                            logging_config = region['application_configuration']['logging']
                            if 'otel_collector' not in logging_config:
                                pos = int(len(logging_config.keys()) / 2)
                                add_key_value_pair(pos, 'otel_collector', 'otelservices-<lob>', logging_config, 'Directs the traces to the LOB gateway')
                                BOGIEFILE_CONTENT_UPDATED = True

                        # added for fargate
                        if 'application_configuration' not in region:
                            region['application_configuration'] = {}
                        if 'logging' not in region['application_configuration']:
                            region['application_configuration']['logging'] = {}
                            logging_config = region['application_configuration']['logging']
                            add_key_value_pair(pos, 'otel_collector', 'otelservices-<lob>', logging_config, 'Directs the traces to the LOB gateway')
                            BOGIEFILE_CONTENT_UPDATED = True
                
                keys = ['java_opts', 'java_options', 'JAVA_OPTS', 'JAVA_OPTIONS']
                if image_type == 'generic' and (contains_key('JAVA_OPTIONS', fargate_container_env) or contains_key('JAVA_OPTS', fargate_container_env)):
                    construct_java_opts = [
                        '-javaagent:/app/otel/otel-javaagent.jar',
                        '-Dotel.service.name=<SERVICE_NAME>',
                        f'-Dotel.exporter.otlp.endpoint=${endpoint}'
                    ]
                    
                    for key in keys:
                        if key in fargate_container_env:
                            current_value = fargate_container_env[key]
                            if isinstance(current_value, list):
                                current_value = ' '.join(current_value)
                            final_java_opts = ' '.join(construct_java_opts) + ' ' + current_value
                            update_key_value_pair(key, final_java_opts, fargate_container_env)
                            BOGIEFILE_CONTENT_UPDATED = True

                if image_type== 'apm' and 'OTEL_ENABLED' not in fargate_container_env:
                    add_key_value_pair(pos, 'OTEL_ENABLED', True, fargate_container_env, 'To turn on OTel')
                    if 'SERVICE_NAME' not in fargate_container_env:
                        add_key_value_pair(pos + 1, 'SERVICE_NAME', '<YOUR SERVICE NAME>', fargate_container_env, 'Replace with your desired service name')
                    BOGIEFILE_CONTENT_UPDATED = True

                if 'OTEL_SERVICE_NAME' not in fargate_container_env:
                    add_key_value_pair(pos + 1, 'OTEL_SERVICE_NAME', '<YOUR SERVICE NAME>', fargate_container_env, 'Replace with your service name')
                    BOGIEFILE_CONTENT_UPDATED = True
                
                if delete_keys('NEWRELIC', fargate_container_env) or upsert_mandatory_tags(pos+1, fargate_container_env, 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags):
                    BOGIEFILE_CONTENT_UPDATED = True
    
    return BOGIEFILE_CONTENT_UPDATED

def process_for_lambda(env: Dict, mandatory_tags: Dict, runtime_version: Optional[str]) -> bool:
    """Processes Lambda environment for OpenTelemetry instrumentation.
    
    Args:
        env: Environment dictionary from Bogiefile
        mandatory_tags: Dictionary of mandatory tags
        runtime_version: Runtime version string
        
    Returns:
        True if updates were made, False otherwise
    """
    account_number = ''
    otel_layer_arn = ''
    layer_region = ''
    arch = ''
    arn_num= ''
    
    if runtime_version is None:
        logging.error("Error: runtime_version is None. Defaulting layer_type to 'proto'.")
        return False
    
    layer_type = 'agent' if 'java' in runtime_version else 'proto'
    AWS_LAMBDA_EXEC_WRAPPER = ''
    C1_OTEL_GATEWAY_ENDPOINT=''
    
    architecture = env['inputs']['architecture'] if 'architecture' in env['inputs'] else 'x86'
    
    if 'name' in env:
        if 'prod' in env['name']:
            account_number = '011108305656'
            C1_OTEL_GATEWAY_ENDPOINT = 'https://otelservices.cloud.capitalone.com:9990'
            arn_num= '3'
        else:
            account_number = '237724329014'
            C1_OTEL_GATEWAY_ENDPOINT = 'https://otelservices.clouddqt.capitalone.com:9990'
            if 'arm' in architecture:
                arn_num = '4'
            else:
                arn_num = '6'
    
    BOGIEFILE_CONTENT_UPDATED = False
    if 'regions' in env:
        for region in env['regions']:
            otel_layer_arn = ''
            otel_extension_arn = ''
            if region['name'] == 'us-east-1':
                layer_region = 'east-1'
            elif region['name'] == 'us-west-2':
                layer_region = 'west-2'

            if 'layer_arns' in region:
                region['layer_arns'] = [arn for arn in region['layer_arns'] if 'NewRelic' not in arn]
                arch = 'ARM' if 'arm' in architecture else ''
                otel_layer_arn = f'arn:aws:lambda:us-{layer_region}:{account_number}:layer:custom-otel-{layer_type}-{runtime_version.replace(".","")}{arch}:1'
                if otel_layer_arn not in region['layer_arns']:
                    region['layer_arns'].append(otel_layer_arn)
                
                otel_extension_arn = f'arn:aws:lambda:us-{layer_region}:{account_number}:layer:otel-collector-extension{arch}:{arn_num}'
                if otel_extension_arn not in region['layer_arns']:
                    region['layer_arns'].append(otel_extension_arn)
                
                BOGIEFILE_CONTENT_UPDATED = True
            else:
                region['layer_arns'] = []
                arch = 'ARM' if 'arm' in architecture else ''
                layer_type = 'agent' 

                otel_layer_arn = f'arn:aws:lambda:us-{layer_region}:{account_number}:layer:custom-otel-{layer_type}-{runtime_version.replace(".","")}{arch}:1'
                if otel_layer_arn not in region['layer_arns']:
                    region['layer_arns'].append(otel_layer_arn)
                
                otel_extension_arn = f'arn:aws:lambda:us-{layer_region}:{account_number}:layer:otel-collector-extension{arch}:{arn_num}'
                if otel_extension_arn not in region['layer_arns']:
                    region['layer_arns'].append(otel_extension_arn)

                BOGIEFILE_CONTENT_UPDATED = True

            if 'environment_variables' not in region:
                region['environment_variables'] = {}
                BOGIEFILE_CONTENT_UPDATED = True
                
            if 'python' in get_runtime(env):
                exec_wrapper = '/opt/otel-instrument'
            elif 'java' in get_runtime(env):
                exec_wrapper = '/opt/otel-handler'
            elif 'nodejs' in get_runtime(env):
                exec_wrapper = '/opt/otel-handler'
            else:
                exec_wrapper = '/opt/otel-handler'
                
            env_vars = {
                'AWS_LAMBDA_EXEC_WRAPPER': exec_wrapper,
                'OTEL_SERVICE_NAME': '<YOUR SERVICE NAME>',
                'OTEL_EXPORTER_OTLP_PROTOCOL': 'http/protobuf',
                'OTEL_EXPORTER_OTLP_ENDPOINT': 'http://localhost:4318',
                'OTEL_EXPORTER_OTLP_METRICS_TIMEOUT': 50,
                'OTEL_EXPORTER_OTLP_TRACES_TIMEOUT': 50,
                'C1_OTEL_GATEWAY_ENDPOINT': C1_OTEL_GATEWAY_ENDPOINT,
                'C1_OTEL_INITIAL_INTERVAL': '10ms',
                'C1_OTEL_MAX_INTERVAL': '5ms',
                'C1_OTEL_MAX_ELAPSED_TIME': '10ms',
                'C1_OTEL_TRANSPORT_TIMEOUT': '75ms'
            }
            
            if 'nodejs' in runtime_version:
                env_vars.update({
                    'OTEL_TRACES_SAMPLER': 'tracidratio',
                    'OTEL_TRACES_SAMPLER_ARG': '1'
                })
            if 'python' in runtime_version:
                check_handler(env)
               
            pos = int(len(region['environment_variables'].keys()) / 2) if region['environment_variables'] else 0
            for key, value in env_vars.items():
                if key not in region['environment_variables']:
                    add_key_value_pair(pos, key, value, region['environment_variables'])
                    pos += 1
                    BOGIEFILE_CONTENT_UPDATED = True
            if delete_keys('NEW_RELIC', region['environment_variables']) or upsert_mandatory_tags(pos+1, region['environment_variables'], 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags):
                BOGIEFILE_CONTENT_UPDATED = True
    return BOGIEFILE_CONTENT_UPDATED 

def process_bogiefile_lines(endpoint: str, asv: str, ba: str, component: str, 
                           image_type: str, file_path: str) -> None:
    """Processes Bogiefile for OpenTelemetry instrumentation.
    
    Args:
        endpoint: OTEL endpoint URL
        asv: ASV tag value
        ba: BA tag value
        component: Component tag value
        image_type: Docker image type
        file_path: Path to Bogiefile
    """
    try:
        data = read_yaml_with_empty_lines('.', 'Bogiefile')
        BOGIEFILE_CONTENT_UPDATED = False
        filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
        
        mandatory_tags = {
            'asv': data['vars'].get('asv', '<YOUR_ASV>'),
            'ba': data['vars'].get('ba', '<YOUR_BA>'),
            'component': data['vars'].get('component', '<YOUR_COMPONENT>')
        }

        for env in filtered_envs:
            gear_name = env['gear']
            
            if 'ecs-fargate:^1' in gear_name:
                BOGIEFILE_CONTENT_UPDATED = process_for_fargate(env,image_type, mandatory_tags) or BOGIEFILE_CONTENT_UPDATED
            elif 'autocruise-express-service:^3' in gear_name:
                BOGIEFILE_CONTENT_UPDATED = process_for_ecs(env, image_type, mandatory_tags) or BOGIEFILE_CONTENT_UPDATED
            elif 'origami:^2' in gear_name:
                BOGIEFILE_CONTENT_UPDATED = process_for_ecs(env, image_type, mandatory_tags) or BOGIEFILE_CONTENT_UPDATED
            elif 'aws-lambda:^4' in gear_name:
                runtime_version = get_runtime(env)
                BOGIEFILE_CONTENT_UPDATED = process_for_lambda(env, mandatory_tags, runtime_version) or BOGIEFILE_CONTENT_UPDATED
        
        if BOGIEFILE_CONTENT_UPDATED:
            top_level_comments = read_top_level_comments('Bogiefile')
            stream = StringIO()
            yaml = ruamel.yaml.YAML()
            yaml.preserve_quotes = True
            yaml.width = 1000
            yaml.indent(mapping=2, sequence=4, offset=2)
            yaml.default_flow_style = False
            yaml.allow_duplicate_keys = True
            
            process_java_opts(data)
            process_policy(data)
            
            yaml.dump(data, stream)
            bogiefile_yaml = f"{top_level_comments}{stream.getvalue()}"
            
            with open('Bogiefile', 'w') as file:
                file.write(bogiefile_yaml)
    except Exception as e:
        logging.error(f"An error occurred in process_bogiefile_lines: {e}")
        
def modify_dockerfile_node(repo_path: str, file_name: str, extracted_values: Dict) -> bool:
    """Modify the Dockerfile by adding OpenTelemetry instrumentation setup for Node.js.
    
    Args:
        repo_path: Path to the repository containing the Dockerfile
        file_name: Name of the Dockerfile
        extracted_values: Dictionary containing extracted values for ASV, BA, and COMPONENT
        
    Returns:
        True if modifications were made, False otherwise
    """
    try: 
        dockerfile_path = os.path.join(repo_path, file_name)
        
        with open(dockerfile_path, "r") as file:
            lines = file.readlines()

        asv_value = extracted_values.get("asv", "")
        ba_value = extracted_values.get("ba", "")
        component_value = extracted_values.get("component", "")
        url_value = extracted_values.get("flavor", "")

        if re.match(r"^(devnav/docker|docker)$", url_value):
            endpoint = "<your-endpoint>"
        elif re.match(r"^(ecs-fargate|container/fargate-api)$", url_value):
            endpoint = "http://localhost:4318"
        elif re.match(r"^(autocruise|ecs-ec2)$", url_value):
            endpoint = "http://172.17.0.1:4318"
        else:
            endpoint = "<your-endpoint>"

        npm_install_present = any("npm install @opentelemetry" in line for line in lines)
        otel_exports_present = any("OTEL_TRACES_EXPORTER" in line for line in lines)

        if npm_install_present and otel_exports_present:
            logging.info("Dockerfile already contains the required lines. No changes made.")
            return False

        modified_lines = lines.copy()
        insert_position = determine_insert_position(lines)

        # Add npm install command if not present
        if not npm_install_present:
            modified_lines.insert(insert_position, NPM_INSTALL_COMMAND + "\n")
            insert_position += 1

        # Add OTEL exports if not present
        if not otel_exports_present:
            otel_exports_filled = OTEL_EXPORTS_TEMPLATE.format(
                asv=asv_value, ba=ba_value, component=component_value, endpoint=endpoint
            )
            modified_lines.insert(insert_position, "\n" + otel_exports_filled + "\n")

        with open(dockerfile_path, "w") as file:
            file.writelines(modified_lines)

        logging.info(f"Updated {file_name}:")
        logging.info(f"  - Added OTEL_EXPORTS_TEMPLATE values asv: {asv_value} ba: {ba_value} component: {component_value}  endpoint: {endpoint}")
        return True
    except Exception as e:
        logging.error(f"An error occurred in modify_dockerfile: {e}")
        return False

#############################################################
# PYTHON-SPECIFIC PROCESSING FUNCTIONS
#############################################################

def add_otel_service_name(data: Dict) -> None:
    """Adds OTEL_SERVICE_NAME only if container_env/container exists, with an inline comment.
    
    Args:
        data: Parsed Bogiefile data
    """
    try:
        if "environments" not in data or not isinstance(data["environments"], list):
            logging.info("No 'environments' section found or it's not a list.")
            return

        for env in data["environments"]:
            if "inputs" in env and isinstance(env["inputs"], dict) and "container_env" in env["inputs"]:
                container_env = env["inputs"]["container_env"]
                
                if isinstance(container_env, dict) and "OTEL_SERVICE_NAME" not in container_env:
                    container_env["OTEL_SERVICE_NAME"] = "<your-app-name>"
                    container_env.yaml_add_eol_comment("Change this to the name of your application", "OTEL_SERVICE_NAME")

    except Exception as e:
        logging.error(f"An error occurred in add_otel_service_name: {e}")

def load_dockerfile(dockerfile_path: str) -> List[str]:
    """Reads the Dockerfile content if it exists.
    
    Args:
        dockerfile_path: Path to the Dockerfile
        
    Returns:
        List of lines from the Dockerfile
    """
    try:
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, "r") as file:
                return file.readlines()
        return []
    except (OSError, IOError) as e:
        logging.error(f"Error reading Dockerfile: {e}")
        return []
    
def remove_unwanted_lines(dockerfile_content: List[str], env_vars: List[str]) -> List[str]:
    """Removes existing OTEL environment variables and 'pip install newrelic' commands.
    
    Args:
        dockerfile_content: List of Dockerfile lines
        env_vars: List of environment variables to remove
        
    Returns:
        Filtered list of Dockerfile lines
    """
    try:
        return [
            line for line in dockerfile_content
            if "pip install newrelic" not in line and not any(line.startswith(env.split("=")[0]) for env in env_vars)
        ]
    except Exception as e:
        logging.error(f"Error in remove_unwanted_lines: {e}")
        return dockerfile_content

def update_cmd_instruction(dockerfile_content: List[str]) -> List[str]:
    """Modifies CMD instruction in Dockerfile to remove NewRelic and add OpenTelemetry.
    
    Args:
        dockerfile_content: List of Dockerfile lines
        
    Returns:
        Modified list of Dockerfile lines
    """
    try:
        for i, line in enumerate(dockerfile_content):
            stripped_line = line.strip()
            if stripped_line.startswith("CMD"):
                try:
                    cmd_parts = json.loads(stripped_line[4:].strip())
                    
                    if isinstance(cmd_parts, list) and len(cmd_parts) > 2:
                        if cmd_parts[0] == "newrelic-admin" and cmd_parts[1] == "run-program":
                            cmd_parts = cmd_parts[2:]

                    if cmd_parts and cmd_parts[0] != "opentelemetry-instrument":
                        cmd_parts.insert(0, "opentelemetry-instrument")

                    dockerfile_content[i] = f'CMD {json.dumps(cmd_parts)}\n'

                except json.JSONDecodeError:
                    pass

        return dockerfile_content
    except Exception as e:
        logging.error(f"Error in update_cmd_instruction: {e}")
        return dockerfile_content

def find_last_pip_install_index(dockerfile_content: List[str]) -> int:
    """Finds the index of the last 'pip install' command in the Dockerfile.
    
    Args:
        dockerfile_content: List of Dockerfile lines
        
    Returns:
        Index of last 'pip install' command, or -1 if not found
    """
    try:
        last_pip_index = -1
        for i, line in enumerate(dockerfile_content):
            if line.strip().startswith("RUN pip install"):
                last_pip_index = i
        return last_pip_index
    except Exception as e:
        logging.error(f"Error in find_last_pip_install_index: {e}")
        return -1

def find_cmd_index(dockerfile_content: List[str]) -> int:
    """Finds the index of the CMD instruction in the Dockerfile.
    
    Args:
        dockerfile_content: List of Dockerfile lines
        
    Returns:
        Index of CMD instruction, or -1 if not found
    """
    try:
        for i, line in enumerate(dockerfile_content):
            if line.strip().startswith("CMD"):
                return i
        return -1
    except Exception as e:
        logging.error(f"Error in find_cmd_index: {e}")
        return -1
    
def ensure_opentelemetry_installed(dockerfile_content: List[str]) -> List[str]:
    """Ensures OpenTelemetry installation commands are added to the Dockerfile.
    
    Args:
        dockerfile_content: List of Dockerfile lines
        
    Returns:
        Modified list of Dockerfile lines
    """
    try:
        otel_install_cmd_distro = "RUN pip install opentelemetry-distro\n"
        otel_install_cmd_otlp = "RUN pip install opentelemetry-exporter-otlp\n"
        otel_bootstrap_cmd = "RUN opentelemetry-bootstrap -a install\n"

        has_distro = any("pip install opentelemetry-distro" in line for line in dockerfile_content)
        has_otlp = any("pip install opentelemetry-exporter-otlp" in line for line in dockerfile_content)
        has_bootstrap = any(otel_bootstrap_cmd.strip() in line for line in dockerfile_content)

        if has_distro and has_otlp and has_bootstrap:
            return dockerfile_content  

        last_pip_index = find_last_pip_install_index(dockerfile_content)
        cmd_index = find_cmd_index(dockerfile_content)

        if last_pip_index != -1:
            insert_index = last_pip_index + 1
        elif cmd_index != -1:
            insert_index = cmd_index
        else:
            insert_index = len(dockerfile_content)

        if not has_distro:
            dockerfile_content.insert(insert_index, "# Install the OpenTelemetry API/SDK exporter package\n")
            insert_index += 1
            dockerfile_content.insert(insert_index, otel_install_cmd_distro)
            insert_index += 1  
        if not has_otlp:
            dockerfile_content.insert(insert_index, "# Install the OpenTelemetry OTLP exporter package\n")
            insert_index += 1
            dockerfile_content.insert(insert_index, otel_install_cmd_otlp)
            insert_index += 1
        if not has_bootstrap:
            dockerfile_content.insert(insert_index, "# Run the opentelemetry-bootstrap command to install the automatic instrumentation agent\n")
            insert_index += 1
            dockerfile_content.insert(insert_index, otel_bootstrap_cmd)
        return dockerfile_content

    except Exception as e:
        logging.error(f"Error in ensure_opentelemetry_installed: {e}")
        return dockerfile_content
    
def determine_insert_position(dockerfile_content: List[str]) -> int:
    """Finds the best position to insert ENV variables safely in a Dockerfile.
    Args:
        dockerfile_content: List of Dockerfile lines
    Returns:
        Optimal index position to insert new ENV variables
    """
    try:
        last_env_index = -1
        cmd_entrypoint_index = -1
        last_run_index = -1
        for i, line in enumerate(dockerfile_content):
            stripped_line = line.strip()
            if stripped_line.startswith("ENV"):
                last_env_index = i
            elif stripped_line.startswith(("CMD", "ENTRYPOINT")) and cmd_entrypoint_index == -1:
                cmd_entrypoint_index = i
            elif stripped_line.startswith("RUN") and "pip install" in stripped_line.lower():
                last_run_index = i
        if last_env_index != -1:
            return last_env_index + 1
        elif last_run_index != -1:
            return last_run_index + 1
        elif cmd_entrypoint_index != -1:
            return cmd_entrypoint_index + 1
        else:
            return len(dockerfile_content)
    except Exception as e:
        logging.error(f"Error in determine_insert_position: {e}")
        return len(dockerfile_content)

def format_env_variables(env_vars: List[str], extracted_values: Dict) -> List[str]:
    """Formats environment variables by replacing placeholders with extracted values.
    Args:
        env_vars: List of environment variable strings with placeholders
        extracted_values: Dictionary containing values to substitute for placeholders
    Returns:
        List of formatted environment variable strings
    """
    try:
        extracted_values = {key: extracted_values.get(key, "") for key in ["asv", "ba", "component"]}
        #return [env.format(**extracted_values) + "\n" for env in env_vars] + ["\n"]
        formatted = [env.format(**extracted_values) + "\n" for env in env_vars]
        return ["\n"] + formatted + ["\n"]
    except KeyError as e:
        logging.error(f"KeyError: Missing key {e} in extracted_values.")
        return []
    except Exception as e:
        logging.error(f"Unexpected error in format_env_variables: {e}")
        return []


def write_dockerfile(dockerfile_path: str, dockerfile_content: List[str]) -> None:
    """Writes the modified content back to the Dockerfile.
    
    Args:
        dockerfile_path: Path to the Dockerfile to write to
        dockerfile_content: List of lines to write
    """
    try:
        with open(dockerfile_path, "w") as file:
            file.writelines(dockerfile_content)
        logging.info(f"Successfully updated Dockerfile: {dockerfile_path}")
    except (OSError, IOError) as e:
        logging.error(f"Error writing to Dockerfile {dockerfile_path}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error writing to Dockerfile: {e}")

def add_env_to_dockerfile(repository_path: str, dockerfile_name: str, 
                         env_vars: List[str], extracted_values: Dict) -> None:
    """Adds environment variables to the Dockerfile and updates instrumentation.
    
    Args:
        repository_path: Path to the repository containing the Dockerfile
        dockerfile_name: Name of the Dockerfile to modify
        env_vars: List of environment variables to add
        extracted_values: Dictionary of values to substitute in the environment variables
    """
    dockerfile_path = os.path.join(repository_path, dockerfile_name)

    try:
        dockerfile_content = load_dockerfile(dockerfile_path)
        if not dockerfile_content:
            logging.warning(f"Warning: {dockerfile_name} is empty or not found.")
            return

        dockerfile_content = remove_unwanted_lines(dockerfile_content, env_vars)
        dockerfile_content = update_cmd_instruction(dockerfile_content)
        dockerfile_content = ensure_opentelemetry_installed(dockerfile_content)

        formatted_env_vars = format_env_variables(env_vars, extracted_values)
        insert_index = determine_insert_position(dockerfile_content)
        dockerfile_content[insert_index:insert_index] = formatted_env_vars

        write_dockerfile(dockerfile_path, dockerfile_content)

        logging.info(f"Updated {dockerfile_name}:")
        logging.info(f"  - Added environment variables at position {insert_index}.")
        logging.info(f"  - Removed 'pip install newrelic' if it was present.")
        logging.info(f"  - Modified CMD to remove 'newrelic-admin run-program' if found.")
        logging.info(f"  - Ensured OpenTelemetry installation commands are correctly added.")

    except (OSError, IOError) as e:
        logging.error(f"Error processing {dockerfile_name}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in {dockerfile_name}: {e}")

def remove_newrelic_requirements(repo_path: str, filename: str) -> None:
    """Removes lines containing 'newrelic==' from the given file.
    
    Args:
        repo_path: Path to the repository containing the requirements file
        filename: Name of the requirements file
    """
    file_path = os.path.join(repo_path, filename)
    
    try:
        if not os.path.exists(file_path):
            logging.info(f"File not found: {file_path}")
            return
        
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        with open(file_path, 'w') as file:
            for line in lines:
                if not re.match(r'^newrelic==', line.strip()):
                    file.write(line)
                    
        logging.info(f"Processed file: {file_path} - removed NewRelic dependencies")
    
    except (OSError, IOError) as e:
        logging.error(f"Error handling file {file_path}: {e}")
        
def write_bogiefile(repository_path: str, data: Dict, top_level_comments: str) -> bool:
    """Writes the modified YAML data back to the Bogiefile while preserving formatting.
    
    Args:
        repository_path: Path to the repository containing the Bogiefile
        data: The modified YAML data structure to write
        top_level_comments: Comments from the top of the original Bogiefile
        
    Returns:
        True if the write operation was successful, False otherwise
    """
    try:
        yaml = ruamel.yaml.YAML()
        yaml.preserve_quotes = True
        yaml.width = 1000
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        yaml.allow_duplicate_keys = True
        
        yaml.representer.ignore_aliases = lambda data: (
            False if hasattr(data, 'anchor') and data.anchor else True
        )

        process_java_opts(data)
        process_policy(data)
        
        with open('./Bogiefile', 'w') as file:
            if top_level_comments:
                file.write(top_level_comments)
                if not top_level_comments.endswith('\n'):
                    file.write('\n')
            
            yaml.dump(data, file)
            
        logging.info('Successfully wrote Bogiefile')
        return True
        
    except Exception as e:
        logging.error(f"An error occurred in write_bogiefile: {e}")
        return False
    
def process_java_repository(repository_path: str = '.') -> None:
    """Processes a Java repository for OpenTelemetry instrumentation.
    
    Args:
        repository_path: Path to the Java repository to process
    """
    try:
        data = read_yaml_with_empty_lines(repository_path, 'Bogiefile')
        deployment_type = find_deployment_type(data)
        endpoint = 'http://localhost:4317' if deployment_type == 'ecs-fargate:^1' else 'http://172.17.0.1:4317'
        asv = data['vars'].get('asv', '<YOUR_ASV>')
        ba = data['vars'].get('ba', '<YOUR_BA>')
        component = data['vars'].get('component', '<YOUR_COMPONENT>')
        pipeline_flavor = data.get('pipeline', {}).get('flavor', '')

        is_lambda = deployment_type == 'aws-lambda:^4' or \
            (isinstance(pipeline_flavor, str) and \
             any(keyword in pipeline_flavor.lower() for keyword in ['lambda', 'serverless']))
        
        dockerfile_exists = find_file_in_repository(repository_path, "Dockerfile") is not None

        if is_lambda:
            process_bogiefile_lines(None, asv, ba, component, None, 'Bogiefile')

            mandatory_tags = {
                'asv': asv,
                'ba': ba,
                'component': component,
                'TRACES_TARGET': '<your_lob_target>',
                'METRICS_TARGET': '<your_lob_target>'
            }
            
            filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
            
            processed_runtimes = set()
            for env in filtered_envs:
                if 'aws-lambda:^4' in env.get('gear', ''):
                    logging.info(f"Processing lambda environment: {env['name']}")
                    runtime_version = get_runtime(env)
                    if runtime_version and 'java' in runtime_version:
                        process_for_lambda(env, mandatory_tags, runtime_version)
                        logging.info(f"Processed lambda configuration for {env['name']} with Java runtime {runtime_version}")
        else:
            if not dockerfile_exists:
                logging.info(f"Skipping {repository_path} - 'Dockerfile' not found and not a lambda deployment")
                return
                
            image_type = check_prerequisites_and_return_image_type(repository_path)
            if not image_type:
                logging.info("Skipping repository - prerequisites not met")
                return
            
            if dockerfile_exists:
                update_settings_in_dockerfile = (
                    does_file_contain_string(repository_path, "Dockerfile", 'java_opts') or 
                    does_file_contain_string(repository_path, "Dockerfile", 'java_options')
                )
                
                update_settings_in_bogiefile = (
                    does_file_contain_string(repository_path, "Bogiefile", 'java_options') or 
                    does_file_contain_string(repository_path, "Bogiefile", 'java_opts')
                )
                
                add_java_opts_if_missing = False
                switch_arg = f"{image_type}_{update_settings_in_dockerfile}_{update_settings_in_bogiefile}"
                if switch_arg == 'generic_False_False':
                    if not does_file_contain_string(repository_path, "Dockerfile", 'USE_MASH_JAVA_OPTIONS'):
                        add_java_opts_if_missing = True
                    process_dockerfile_lines(endpoint, asv, ba, component, image_type, 'Dockerfile', add_java_opts_if_missing)
                    process_bogiefile_lines(endpoint, asv, ba, component, image_type, 'Bogiefile')
                elif switch_arg == 'generic_True_False':
                    if not does_file_contain_string(repository_path, "Dockerfile", 'USE_MASH_JAVA_OPTIONS'):
                        add_java_opts_if_missing = True
                    process_dockerfile_lines(endpoint, asv, ba, component, image_type, 'Dockerfile', add_java_opts_if_missing)
                    process_bogiefile_lines(endpoint, asv, ba, component, image_type, 'Bogiefile')
                elif switch_arg == 'generic_False_True':
                    process_dockerfile_lines(endpoint, asv, ba, component, image_type, 'Dockerfile')
                    process_bogiefile_lines(endpoint, asv, ba, component, image_type, 'Bogiefile')
                elif switch_arg in ['distroless_True_False', 'distroless_False_True', 'distroless_True_True']:
                    process_dockerfile_lines(endpoint, asv, ba, component, image_type, 'Dockerfile')
                    process_bogiefile_lines(endpoint, asv, ba, component, image_type, 'Bogiefile')
                
                if does_dockerfile_contains_otel_supported_image('Dockerfile'):
                    process_bogiefile_lines(endpoint, asv, ba, component, image_type, 'Bogiefile')
                    lines = omit_newrelic_vars_from_dockerfile('Dockerfile')
                    if lines:
                        with open('Dockerfile', 'w') as file:
                            file.writelines(lines)
            else:
                process_bogiefile_lines(endpoint, asv, ba, component, image_type, 'Bogiefile')
        
        logging.info("Migration completed successfully")
    except Exception as e:
        logging.error(f"An error occurred during migration: {e}")
        raise
    
def process_node_repository(repository_path: str = '.') -> None:
    """Processes a Node.js repository for OpenTelemetry instrumentation.
    
    Args:
        repository_path: Path to the Node.js repository to process
    """
    try:

        if not os.path.isdir(repository_path):
            logging.error(f"Invalid repository path: {repository_path}")
            return

        if find_file_in_repository(repository_path, "Bogiefile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Bogiefile' not found", "info")
            return
        
        data = read_yaml_with_empty_lines(repository_path, "Bogiefile")
        top_level_comments = read_top_level_comments("Bogiefile")
        
        deployment_type = find_deployment_type(data)
        # is_lambda = deployment_type == 'aws-lambda:^4' or (
        #     'flavor' in data and isinstance(data['flavor'], str) and 'lambda' in data['flavor'].lower()
        # )
        pipeline_flavor = data.get('pipeline', {}).get('flavor', '')

        is_lambda = deployment_type == 'aws-lambda:^4' or \
            (isinstance(pipeline_flavor, str) and \
             any(keyword in pipeline_flavor.lower() for keyword in ['lambda', 'serverless']))
        dockerfile_exists = find_file_in_repository(repository_path, "Dockerfile") is not None
        
        extracted_values = extract_values_case_insensitive(data, ["asv", "ba", "component", "flavor"])
        logging.debug(f"Extracted values: {extracted_values}")
        
        dockerfile_exists = find_file_in_repository(repository_path, "Dockerfile") is not None
        if not is_lambda and not dockerfile_exists:
            log_and_exit(f"Skipping {repository_path} - 'Dockerfile' not found and not a lambda deployment", "info")
            return
        
        delete_keys_matching_pattern(data, NEW_RELIC_PATTERN)
        
        if is_lambda:
            mandatory_tags = {
                'asv': extracted_values.get('asv', '<YOUR_ASV>'),
                'ba': extracted_values.get('ba', '<YOUR_BA>'),
                'component': extracted_values.get('component', '<YOUR_COMPONENT>'),
                'TRACES_TARGET': '<your_lob_target>',
                'METRICS_TARGET': '<your_lob_target>'
            }
            
            filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
            
            processed_runtimes = set()
            for env in filtered_envs:
                if 'aws-lambda:^4' in env.get('gear', ''):
                    logging.info(f"Processing lambda environment: {env['name']}")
                    runtime_version = get_runtime(env)
                    if runtime_version and 'nodejs' in runtime_version:
                        process_for_lambda(env, mandatory_tags, runtime_version)
                        logging.info(f"Processed lambda configuration for {env['name']} with Node runtime {runtime_version}")
        elif dockerfile_exists:
            modify_dockerfile_node(repository_path, "Dockerfile", extracted_values)
        
        stream = StringIO()
        yaml = ruamel.yaml.YAML()
        yaml.preserve_quotes = True
        yaml.width = 1000
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        yaml.allow_duplicate_keys = True
        process_java_opts(data)
        process_policy(data)
        yaml.dump(data, stream)
        bogiefile_yaml = f"{top_level_comments}{stream.getvalue()}"
        with open('./Bogiefile', 'w') as file:
            file.write(bogiefile_yaml)

        log_and_exit(f"Successfully processed nodejs repository: {repository_path}", "info")
    except Exception as e:
        logging.error(f"Error processing repository: {e}")
        
def process_python_repository(repository_path: str = '.') -> None:
    """Processes a Python repository for OpenTelemetry instrumentation.
    
    Args:
        repository_path: Path to the Python repository to process
    """
    try:

        if not os.path.isdir(repository_path):
            logging.error(f"Invalid repository path: {repository_path}")
            return

        if find_file_in_repository(repository_path, "Bogiefile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Bogiefile' not found", "info")
            return

        data = read_yaml_with_empty_lines(repository_path, "Bogiefile")
        top_level_comments = read_top_level_comments("Bogiefile")
        
        deployment_type = find_deployment_type(data)
        pipeline_flavor = data.get('pipeline', {}).get('flavor', '')
        
        # Check for lambda/serverless in pipeline flavor only
        is_lambda = deployment_type == 'aws-lambda:^4' or \
            (isinstance(pipeline_flavor, str) and \
             any(keyword in pipeline_flavor.lower() for keyword in ['lambda', 'serverless']))
        dockerfile_exists = find_file_in_repository(repository_path, "Dockerfile") is not None
        
        extracted_values = extract_values_case_insensitive(data, ["asv", "ba", "component"])
        logging.debug(f"Extracted values: {extracted_values}")
        
        if not is_lambda and not dockerfile_exists:
            log_and_exit(f"Skipping {repository_path} - 'Dockerfile' not found and not a lambda deployment", "info")
            return
    

        process_bogiefile_lines("NA", "asv", "ba", "component", "ecs-fargate:^1", "Bogiefile")

        delete_keys_matching_pattern(data, NEW_RELIC_PATTERN)
        add_otel_service_name(data)
        
        if is_lambda:
            mandatory_tags = {
                'asv': extracted_values.get('asv', '<YOUR_ASV>'),
                'ba': extracted_values.get('ba', '<YOUR_BA>'),
                'component': extracted_values.get('component', '<YOUR_COMPONENT>'),
                'TRACES_TARGET': '<your_lob_target>',
                'METRICS_TARGET': '<your_lob_target>'
            }
            
            filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
            
            # Process each lambda environment
            for env in filtered_envs:
                if 'aws-lambda:^4' in env.get('gear', ''):
                    runtime_version = get_runtime(env)
                    if runtime_version and 'python' in runtime_version:
                        process_for_lambda(env, mandatory_tags, runtime_version)
                        logging.info(f"Processed lambda configuration for {env['name']} with Python runtime {runtime_version}")
        elif dockerfile_exists:
            add_env_to_dockerfile(repository_path, "Dockerfile", PYTHON_ENVIRONMENT_VARIABLES, extracted_values)
        
        write_bogiefile(repository_path, data, top_level_comments)

        remove_newrelic_requirements(repository_path, 'requirements.txt')
            
        log_and_exit(f"Successfully processed python repository: {repository_path}", "info")
    except Exception as e:
        logging.error(f"Error processing repository: {e}")
        
def clone_repository(github_url: str) -> Optional[str]:
    """Clone a GitHub repository to a temporary directory.
    
    Args:
        github_url: URL of the GitHub repository
        
    Returns:
        Path to the cloned repository or None if failed
    """
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        repo_name = github_url.split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        repo_dir = os.path.join(temp_dir, repo_name)
        
        # Clone the repository
        subprocess.run(['git', 'clone', github_url, repo_dir], check=True)
        
        return repo_dir
    except Exception as e:
        logging.error(f"Failed to clone repository {github_url}: {e}")
        return None


def main():
    """CLI entry point with new field display"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python repo_analyzer.py <github_repo_url>")
        print("  python repo_analyzer.py --csv <input_csv_file> [output_csv_file]")
        print("  python repo_analyzer.py --parallel <input_csv_file> [output_csv_file] [max_workers]")
        sys.exit(1)

    if sys.argv[1] == "--parallel":
        if len(sys.argv) < 3:
            print("Error: Please provide input CSV file")
            print("Usage: python repo_analyzer.py --parallel <input_csv_file> [output_csv_file] [max_workers]")
            sys.exit(1)
        
        input_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        max_workers = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        
        # Cap max_workers to prevent too many simultaneous API requests
        max_workers = min(max_workers, 100)
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
        github_url = sys.argv[1]
        analyzer = GitHubRepoAnalyzer()

        result = analyzer.analyze_repository(github_url)

        print("\n=== Analysis Results ===")
        print(f"Repository: {result.repository}")
        if result.error:
            print(f"Error: {result.error}")
        else:
            print(f"Language: {result.language}")
            print(f"Archived: {'TRUE' if result.archived else 'FALSE'}")
            print(f"Flavor: {result.flavor or 'Not specified'}")
            print(f"Supported Flavor: {'TRUE' if result.supported else 'FALSE'}")
            print(f"Manual Case: {'TRUE' if result.MANUAL_CASE else 'FALSE'}")
            print(f"OTEL Onboarded: {'TRUE' if result.OTEL_Onboarded else 'FALSE'}")
            print(f"Auto Instrumentation Compatible: {'TRUE' if result.auto_instrumentation else 'FALSE'}")
            print(f"New Relic detected: {'TRUE' if result.has_newrelic else 'FALSE'}")
            print(f"Micrometer detected: {'TRUE' if result.has_micrometer else 'FALSE'}")
            print(f"Prometheus detected: {'TRUE' if result.has_prometheus else 'FALSE'}")
            print(f"AWS Lambda Powertools detected: {'TRUE' if result.has_aws_lambda_powertools else 'FALSE'}")
            print(f"Logging frameworks: {', '.join(result.logging_frameworks) if result.logging_frameworks else 'None'}")
            print(f"Monitoring frameworks: {', '.join(result.monitoring_frameworks) if result.monitoring_frameworks else 'None'}")
            print(f"Recommendation: {result.recommendation}")
            print(f"Reason: {result.reason}")
            
            if "details" in result and result["details"]:
                # Print auto-instrumentation details if they exist
                if "auto_instrumentation" in result["details"]:
                    ai = result["details"]["auto_instrumentation"]
                    if ai.get("frameworks"):
                        print("\n=== Auto-Instrumentation Details ===")
                        print("Supported frameworks detected:")
                        for fw in ai["frameworks"]:
                            # Print framework name and version if available
                            framework_name = fw.get('framework') or fw.get('server', 'Unknown')
                            version = fw.get('version', 'version not specified')
                            print(f"  - {framework_name} (version: {version})")
                
                # Print custom metrics details if they exist
                if "custom_metrics" in result["details"]:
                    cm = result["details"]["custom_metrics"]
                    if cm.get("patterns_found"):
                        print("\n=== Custom Metrics Details ===")
                        print("Patterns found in code:")
                        for pattern in cm["patterns_found"]:
                            print(f"  - {pattern}")
                    
                    # Print additional custom metrics info if available
                    if cm.get("libraries"):
                        print("\nCustom metrics libraries detected:")
                        for lib, detected in cm["libraries"].items():
                            if detected:
                                print(f"  - {lib}")
                    
                    if cm.get("config_files"):
                        print("\nConfiguration files with custom metrics:")
                        for config_file in cm["config_files"]:
                            print(f"  - {config_file}")
                            

            if result.auto_instrumentation:
                print("\nThis repository is compatible with auto-instrumentation.")
                confirmation = input("Would you like to proceed with the OpenTelemetry instrumentation changes? (yes/no): ")
                if confirmation.lower() in ['yes', 'y']:
                    try:
                        # Determine if we need to clone the repo or use local path
                        if github_url.startswith(('http://', 'https://')):
                            # Clone the repository
                            repo_dir = clone_repository(github_url)
                            if not repo_dir:
                                print("Failed to clone repository")
                                return
                        else:
                            # Use local path directly
                            repo_dir = github_url
                        
                        # Process based on language
                        language = result.language.lower()
                        if language == "java":
                            process_java_repository(repo_dir)
                        elif language == "python":
                            process_python_repository(repo_dir)
                        elif language == "nodejs":
                            process_node_repository(repo_dir)
                        else:
                            print(f"\nUnsupported language for auto-instrumentation: {language}")
                            return
                        
                        print("\nOpenTelemetry instrumentation completed successfully!")
                        print("Please review the changes before committing them.")
                        
                        # Clean up if we cloned the repo
                        # if github_url.startswith(('http://', 'https://')):
                        #     shutil.rmtree(repo_dir, ignore_errors=True)
                            
                    except Exception as e:
                        logging.error(f"Error during instrumentation: {e}")
                        print("\nError occurred during instrumentation. Please check logs for details.")
                        # Clean up if we cloned the repo and had an error
                        # if 'repo_dir' in locals() and github_url.startswith(('http://', 'https://')):
                        #     shutil.rmtree(repo_dir, ignore_errors=True)
                else:
                    print("\nOperation cancelled by user.")
                
if __name__ == "__main__":
    main()