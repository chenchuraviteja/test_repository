#!/usr/bin/env python3
"""
OpenTelemetry Migration Tool

This script automates the migration from New Relic to OpenTelemetry instrumentation
for applications written in Java, Python, or Node.js. It modifies configuration files
(Bogiefile, Dockerfile) and adds appropriate OpenTelemetry instrumentation based on
the application's language and deployment type.
"""

import os
import logging
import sys
import re
import json
import argparse
import ruamel.yaml
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, LiteralScalarString
from ruamel.yaml.compat import StringIO
from typing import Optional, Dict, List, Union, Any

#############################################################
# CONFIGURATION AND CONSTANTS
#############################################################

# General configuration constants
NEW = '.new'
EXECUTED_IN_CODEGENIE = os.environ.get("HOSTNAME") is not None
DOCKER_IMAGE_PATTERN = re.compile(r"FROM\s")
NEW_RELIC_PATTERN = r'(?i)^new[_]?relic.*'

# Supported gear types
ALLOWLISTED_GEARS = ['autocruise-express-service:^3', 'ecs-fargate:^1', 'aws-lambda:^4']

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
# COMMAND LINE INTERFACE
#############################################################

def cli_setup() -> argparse.Namespace:
    """Set up command line argument parser.
    
    Returns:
        Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Tool for migrating from New Relic to OpenTelemetry instrumentation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        "--newRelicAccountIds",
        required=True,
        help="New Relic account IDs delimited by comma"
    )
    
    # Optional arguments
    parser.add_argument(
        "--asvs",
        required=False,
        help="Optional ASVs to filter"
    )
    parser.add_argument(
        "--mappingFilePath",
        help="File of Policy GUIDs to filter for conversion"
    )
    
    # Testing and diagnostic flags
    parser.add_argument(
        "-R", "--reload",
        action="store_true",
        help="Reload from source"
    )
    parser.add_argument(
        "-D", "--debug",
        action="store_true",
        help="Enable debug logging level"
    )
    
    return parser.parse_args()

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
    logging.info("Detecting repository language.")
    
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
            resource_attributes = resource_attributes.replace('"','')
    
    for tag in tags:
        if resource_attributes.upper().find(tag.upper()) == -1:
            resource_attributes = resource_attributes + 'tags.'+tag.upper()+'='+tags[tag]+','
            resources_attributes_updated = True

    if resources_attributes_updated:
        resource_attributes = resource_attributes[:-1]
        if is_quoted:
            resource_attributes = '"'+resource_attributes+'"'
        add_key_value_pair(pos, key, resource_attributes, root)
           
    return resources_attributes_updated

#############################################################
# JAVA-SPECIFIC PROCESSING FUNCTIONS
#############################################################

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
        if contains_key('JAVA_OPTIONS', container_env) or contains_key('JAVA_OPTS', container_env):
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

def process_for_fargate(env: Dict, mandatory_tags: Dict) -> bool:
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
                
                keys = ['java_opts', 'java_options', 'JAVA_OPTS', 'JAVA_OPTIONS']
                if contains_key('JAVA_OPTIONS', fargate_container_env) or contains_key('JAVA_OPTS', fargate_container_env):
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
                
                if 'OTEL_SERVICE_NAME' not in fargate_container_env:
                    add_key_value_pair(pos + 1, 'OTEL_SERVICE_NAME', '<YOUR SERVICE NAME>', fargate_container_env, 'Replace with your service name')
                    BOGIEFILE_CONTENT_UPDATED = True
                
                if delete_keys('NEWRELIC', fargate_container_env) or upsert_mandatory_tags(pos+1, fargate_container_env, 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags):
                    BOGIEFILE_CONTENT_UPDATED = True
    
    return BOGIEFILE_CONTENT_UPDATED

#############################################################
# LAMBDA PROCESSING FUNCTIONS
#############################################################

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
                BOGIEFILE_CONTENT_UPDATED = process_for_fargate(env, mandatory_tags) or BOGIEFILE_CONTENT_UPDATED
            elif 'autocruise-express-service:^3' in gear_name:
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

#############################################################
# NODE.JS-SPECIFIC PROCESSING FUNCTIONS
#############################################################

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

        modified_lines = []
        workdir_found = False
        npm_added = False

        for line in lines:
            modified_lines.append(line)

            if line.strip().startswith("WORKDIR"):
                modified_lines.append("\n")
                workdir_found = True

            if workdir_found and not npm_install_present:
                modified_lines.append(NPM_INSTALL_COMMAND)
                npm_added = True
                workdir_found = False

            if npm_added and not otel_exports_present:
                otel_exports_filled = OTEL_EXPORTS_TEMPLATE.format(
                    asv=asv_value, ba=ba_value, component=component_value, endpoint=endpoint
                )
                modified_lines.append("\n" + otel_exports_filled)
                npm_added = False

        with open(dockerfile_path, "w") as file:
            file.writelines(modified_lines)

        logging.info("Dockerfile updated successfully!")
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

        for i, line in enumerate(dockerfile_content):
            stripped_line = line.strip()
            
            if stripped_line.startswith("ENV"):
                last_env_index = i
            elif stripped_line.startswith(("CMD", "ENTRYPOINT")) and cmd_entrypoint_index == -1:
                cmd_entrypoint_index = i

        if last_env_index != -1:
            return last_env_index + 1
        elif cmd_entrypoint_index != -1:
            return cmd_entrypoint_index
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
        return [env.format(**extracted_values) + "\n" for env in env_vars] + ["\n"]
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

#############################################################
# MAIN REPOSITORY PROCESSING FUNCTIONS
#############################################################

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
        
        is_lambda = deployment_type == 'aws-lambda:^4' or (
            'flavor' in data and isinstance(data['flavor'], str) and 'lambda' in data['flavor'].lower()
        )
        
        dockerfile_exists = find_file_in_repository(repository_path, "Dockerfile") is not None

        if is_lambda:
            process_bogiefile_lines(None, asv, ba, component, None, 'Bogiefile')
            
            mandatory_tags = {
                'asv': asv,
                'ba': ba,
                'component': component
            }
            
            filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
            
            processed_runtimes = set()
            for env in filtered_envs:
                if 'aws-lambda:^4' in env.get('gear', '') or ('flavor' in env and 'lambda' in str(env['flavor']).lower()):
                    runtime_version = get_runtime(env)
                    if runtime_version and 'java' in runtime_version and runtime_version not in processed_runtimes:
                        process_for_lambda(env, mandatory_tags, runtime_version)
                        processed_runtimes.add(runtime_version)
                        logging.info(f"Processed lambda configuration for Java runtime {runtime_version}")
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
        logging.info(f"Processing local repository at: {repository_path}")

        if not os.path.isdir(repository_path):
            logging.error(f"Invalid repository path: {repository_path}")
            return

        if find_file_in_repository(repository_path, "Bogiefile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Bogiefile' not found", "info")
            return
        
        data = read_yaml_with_empty_lines(repository_path, "Bogiefile")
        top_level_comments = read_top_level_comments("Bogiefile")
        
        deployment_type = find_deployment_type(data)
        is_lambda = deployment_type == 'aws-lambda:^4' or (
            'flavor' in data and isinstance(data['flavor'], str) and 'lambda' in data['flavor'].lower()
        )
        
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
                'component': extracted_values.get('component', '<YOUR_COMPONENT>')
            }
            
            filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
            
            processed_runtimes = set()
            for env in filtered_envs:
                if 'aws-lambda:^4' in env.get('gear', '') or ('flavor' in env and 'lambda' in str(env['flavor']).lower()):
                    runtime_version = get_runtime(env)
                    if runtime_version and 'nodejs' in runtime_version and runtime_version not in processed_runtimes:
                        process_for_lambda(env, mandatory_tags, runtime_version)
                        processed_runtimes.add(runtime_version)
                        logging.info(f"Processed lambda configuration for Node.js runtime {runtime_version}")
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
        logging.info('Successfully processed Node.js repository')

        log_and_exit(f"Successfully processed nodejs repository: {repository_path}", "info")
    except Exception as e:
        logging.error(f"Error processing repository: {e}")

def process_python_repository(repository_path: str = '.') -> None:
    """Processes a Python repository for OpenTelemetry instrumentation.
    
    Args:
        repository_path: Path to the Python repository to process
    """
    try:
        logging.info(f"Processing local repository at: {repository_path}")

        if not os.path.isdir(repository_path):
            logging.error(f"Invalid repository path: {repository_path}")
            return

        if find_file_in_repository(repository_path, "Bogiefile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Bogiefile' not found", "info")
            return

        data = read_yaml_with_empty_lines(repository_path, "Bogiefile")
        top_level_comments = read_top_level_comments("Bogiefile")
        
        deployment_type = find_deployment_type(data)
        is_lambda = deployment_type == 'aws-lambda:^4' or (
            'flavor' in data and isinstance(data['flavor'], str) and 'lambda' in data['flavor'].lower()
        )
        
        dockerfile_exists = find_file_in_repository(repository_path, "Dockerfile") is not None
        
        extracted_values = extract_values_case_insensitive(data, ["asv", "ba", "component"])
        logging.debug(f"Extracted values: {extracted_values}")
        
        if not is_lambda and not dockerfile_exists:
            log_and_exit(f"Skipping {repository_path} - 'Dockerfile' not found and not a lambda deployment", "info")
            return
        
        if does_file_contain_string(repository_path, "Bogiefile", "newrelic") == True and \
           does_file_contain_string(repository_path, "Bogiefile", "NEWRELIC") == True and \
           ((dockerfile_exists and does_file_contain_string(repository_path, "Dockerfile", "newrelic") == True and 
             does_file_contain_string(repository_path, "Dockerfile", "NEWRELIC") == True) or not dockerfile_exists):
            return 
    
        process_bogiefile_lines("NA", "asv", "ba", "component", "ecs-fargate:^1", "Bogiefile")

        delete_keys_matching_pattern(data, NEW_RELIC_PATTERN)
        add_otel_service_name(data)
        
        if is_lambda:
            mandatory_tags = {
                'asv': extracted_values.get('asv', '<YOUR_ASV>'),
                'ba': extracted_values.get('ba', '<YOUR_BA>'),
                'component': extracted_values.get('component', '<YOUR_COMPONENT>')
            }
            
            filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
            
            processed_runtimes = set()
            for env in filtered_envs:
                if 'aws-lambda:^4' in env.get('gear', '') or ('flavor' in env and 'lambda' in str(env['flavor']).lower()):
                    runtime_version = get_runtime(env)
                    if runtime_version and 'python' in runtime_version and runtime_version not in processed_runtimes:
                        process_for_lambda(env, mandatory_tags, runtime_version)
                        processed_runtimes.add(runtime_version)
                        logging.info(f"Processed lambda configuration for Python runtime {runtime_version}")
        elif dockerfile_exists:
            add_env_to_dockerfile(repository_path, "Dockerfile", PYTHON_ENVIRONMENT_VARIABLES, extracted_values)
        
        write_bogiefile(repository_path, data, top_level_comments)
        logging.info('Successfully processed Python repository')

        remove_newrelic_requirements(repository_path, 'requirements.txt')
            
        log_and_exit(f"Successfully processed python repository: {repository_path}", "info")
    except Exception as e:
        logging.error(f"Error processing repository: {e}")

def process_repository_directory(repository_path: str = '.') -> None:
    """Main function to process a repository based on its language.
    
    Args:
        repository_path: Path to the repository to process
    """
    try:
        language = detect_repository_language(repository_path)
        
        if language == "java":
            process_java_repository(repository_path)
        elif language == "python":
            process_python_repository(repository_path)
        elif language == "nodejs":
            process_node_repository(repository_path)
        else:
            log_and_exit(f"Skipping {repository_path} - Unsupported language: {language}", "info")
    except Exception as e:
        logging.error(f"Error processing repository: {e}")

def main() -> None:
    """Main entry point for the script."""
    try:
        args = cli_setup()
        configure_logging(args.debug)
        
        logging.info("Starting OpenTelemetry migration tool")
        logging.debug(f"Command line arguments: {args}")
        
        repository_path = '.'
        process_repository_directory(repository_path)
        
        logging.info("Migration process completed successfully")
    except Exception as e:
        logging.error(f"Fatal error in main execution: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()