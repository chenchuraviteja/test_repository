#!/usr/bin/env python3
"""
GitHub Repository Analyzer

This script analyzes GitHub repositories to:
1. Identify the primary language
2. Detect if the repo uses custom metrics or spans
3. Check if it can be supported by OpenTelemetry auto-instrumentation
4. Identify if it's a Golang repository
5. Provide appropriate guidance based on the findings
"""

import os
import sys
import json
import re
import requests
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
        
        # Load supported frameworks for Java and Node.js
        self.java_frameworks = self._parse_java_frameworks()
        self.node_frameworks = self._parse_node_frameworks()

    def _parse_java_frameworks(self):
        """Parse supported Java frameworks data"""
        # Simplified framework data - in a real implementation, this would come from a file
        return {
            "libraries": ["spring", "hibernate", "apache httpclient", "jetty", "tomcat"],
            "app_servers": ["tomcat", "jetty", "wildfly", "jboss", "websphere", "weblogic"],
            "jvms": ["openjdk", "oracle hotspot", "ibm", "openj9", "zulu"]
        }

    def _parse_node_frameworks(self):
        """Parse supported Node.js frameworks data"""
        # Simplified framework data - in a real implementation, this would come from a file
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
            # Golang typically requires manual instrumentation
            return {"has_custom_metrics": False, "reason": "Golang typically requires manual instrumentation"}
        
        return {"has_custom_metrics": False, "reason": "Language not analyzed for custom metrics"}

    def _check_java_custom_metrics(self, owner, repo):
        """Check Java repositories for Micrometer or New Relic libraries"""
        pom_content = self.download_file(owner, repo, "pom.xml")
        if not pom_content:
            return {
                "has_custom_metrics": False,
                "libraries": {},
                "reason": "No pom.xml found"
            }
        
        has_micrometer = False
        has_newrelic = False
        
        # Try to parse as XML
        try:
            wrapped_content = f"<root>{pom_content}</root>"
            root = ET.fromstring(wrapped_content)
            
            # Look for dependencies
            dependencies = root.findall(".//dependency")
            for dep in dependencies:
                group_id = dep.find("groupId")
                artifact_id = dep.find("artifactId")
                
                if group_id is not None and artifact_id is not None:
                    if "micrometer" in group_id.text.lower() or "micrometer" in artifact_id.text.lower():
                        has_micrometer = True
                    if "newrelic" in group_id.text.lower() or "newrelic" in artifact_id.text.lower():
                        has_newrelic = True
        except ET.ParseError:
            # Fallback to regex
            if re.search(r'<groupId>io\.micrometer</groupId>|<artifactId>micrometer', pom_content, re.IGNORECASE):
                has_micrometer = True
            if re.search(r'<groupId>com\.newrelic</groupId>|<artifactId>newrelic', pom_content, re.IGNORECASE):
                has_newrelic = True
        
        return {
            "has_custom_metrics": has_micrometer or has_newrelic,
            "libraries": {
                "micrometer": has_micrometer,
                "newrelic": has_newrelic
            },
            "reason": "Micrometer or New Relic detected" if (has_micrometer or has_newrelic) else "No custom metrics libraries detected"
        }

    def _check_nodejs_custom_metrics(self, owner, repo):
        """Check Node.js repositories for New Relic libraries"""
        package_json = self.download_file(owner, repo, "package.json")
        if not package_json:
            return {
                "has_custom_metrics": False,
                "libraries": {},
                "reason": "No package.json found"
            }
        
        has_newrelic = False
        
        try:
            package_data = json.loads(package_json)
            
            # Check dependencies
            for dep_name in package_data.get("dependencies", {}):
                if "newrelic" in dep_name.lower():
                    has_newrelic = True
                    break
            
            # Check devDependencies if not found in dependencies
            if not has_newrelic:
                for dep_name in package_data.get("devDependencies", {}):
                    if "newrelic" in dep_name.lower():
                        has_newrelic = True
                        break
                    
        except json.JSONDecodeError:
            if re.search(r'[\'\"](newrelic|@newrelic)[\'\"]: [\'\"](\\^|~|>=)?\\d', package_json, re.IGNORECASE):
                has_newrelic = True
        
        # Check common JS files for imports if not found in package.json
        if not has_newrelic:
            common_js_files = ["index.js", "app.js", "server.js", "src/main.js"]
            for file_path in common_js_files:
                content = self.download_file(owner, repo, file_path)
                if content and re.search(r'(require|import).*[\'\"](newrelic|@newrelic)', content, re.IGNORECASE):
                    has_newrelic = True
                    break
        
        return {
            "has_custom_metrics": has_newrelic,
            "libraries": {"newrelic": has_newrelic},
            "reason": "New Relic detected" if has_newrelic else "No custom metrics libraries detected"
        }

    def _check_python_custom_metrics(self, owner, repo):
        """Check Python repositories for New Relic libraries"""
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
        
        return {
            "has_custom_metrics": result['newrelic'],
            "libraries": {"newrelic": result['newrelic']},
            "reason": "New Relic detected" if result['newrelic'] else "No custom metrics libraries detected"
        }
    

    def check_auto_instrumentation(self, owner, repo, language):
        """Check if repository can be supported by OpenTelemetry auto-instrumentation"""
        language_lower = language.lower() if language else ""
        
        if language_lower == "java":
            return self._check_java_auto_instrumentation(owner, repo)
        elif language_lower in ["javascript", "typescript", "nodejs", "node"]:
            return self._check_nodejs_auto_instrumentation(owner, repo)
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
                "reason": None
            }
            
            # Step 2: Check for custom metrics/spans
            if language:
                custom_metrics_result = self.check_custom_metrics(owner, repo, language)
                result["custom_metrics"] = custom_metrics_result["has_custom_metrics"]
                print(f"Custom metrics/spans detected: {'Yes' if result['custom_metrics'] else 'No'}")
                if result["custom_metrics"]:
                    print(f"  Reason: {custom_metrics_result['reason']}")
            else:
                result["custom_metrics"] = False
                print("Skipping custom metrics check - language not detected")
            
            # Step 3: Check for auto-instrumentation compatibility
            if language:
                auto_instrumentation_result = self.check_auto_instrumentation(owner, repo, language)
                result["auto_instrumentation"] = auto_instrumentation_result["compatible"]
                print(f"Auto-instrumentation compatible: {'Yes' if result['auto_instrumentation'] else 'No'}")
                print(f"  Reason: {auto_instrumentation_result['reason']}")
            else:
                result["auto_instrumentation"] = False
                print("Skipping auto-instrumentation check - language not detected")
            
            # Step 5: Determine if it's Golang
            if result["is_golang"]:
                print("Repository is Golang - typically requires manual instrumentation")
            
            # Determine recommendation based on analysis
            if result["is_golang"]:
                result["recommendation"] = "Use Windsurf for Golang instrumentation"
                result["reason"] = "Golang typically requires manual instrumentation"
            elif result["custom_metrics"]:
                result["recommendation"] = "Use Windsurf for custom metrics/spans"
                result["reason"] = "Custom metrics/spans detected"
            elif result["auto_instrumentation"]:
                result["recommendation"] = "Use OpenTelemetry auto-instrumentation"
                result["reason"] = "Compatible with auto-instrumentation"
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

def main():
    """CLI entry point"""
    if len(sys.argv) != 2:
        print("Usage: python repo_analyzer.py <github_repo_url>")
        sys.exit(1)

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

if __name__ == "__main__":
    main()