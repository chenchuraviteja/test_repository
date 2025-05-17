import os
import logging
import sys
import re
import json
import ruamel.yaml
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, LiteralScalarString
from ruamel.yaml.compat import StringIO
from typing import Optional

NEW = '.new'
EXECUTED_IN_CODEGENIE = os.environ.get("HOSTNAME") is not None
JAR_FILE_NAME_PATTERN_JAVAOPTS = r'\b[A-Za-z_]*JAVA_OPT[A-Za-z_]+\s*=\s*["\'][^"\']*-javaagent:[^\s]*otel[-\w]*\.jar[^"\']*["\']'
JAR_FILE_NAME_PATTERN_CMD = r'(CMD).*(otel-javaagent.jar|otel.jar)'
ARTIFACTORY_IMAGE_PATTERN = 'artifactory-edge-staging.cloud.capitalone.com/'
DOCKER_IMAGE_PATTERN = re.compile(r"FROM\s")
ALLOWLISTED_GEARS = ['autocruise-express-service:^3', 'ecs-fargate:^1', 'aws-lambda:^4']
APM_SUPPORTED_IMAGE_PREFIX = 'artifactory-edge-staging.cloud.capitalone.com/bacloudosimages-docker/cof-approved-images/apm'
PLEC_APM_SUPPORTED_IMAGE_PREFIX = 'artifactory-edge-staging.cloud.capitalone.com/baenterprisesharedimages-docker/languages/java'
TOMCAT_SUPPORTED_IMAGE_PREFIX = 'artifactory-edge-staging.cloud.capitalone.com/bacloudosimages-docker/cof-approved-images/tomcat'
NEW_RELIC_PATTERN = r'(?i)^new[_]?relic.*'

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

# Configure logging
if EXECUTED_IN_CODEGENIE:
    logPath = f"/app/logs/{os.environ.get('HOSTNAME')}_logs/app.log"
    logging.basicConfig(filename=logPath, level=logging.INFO)
    logging.info(f"Logger config file has been configured for {logPath}")
else:
    logging.basicConfig(level=logging.INFO)
    logging.info("Running in local mode")

# Common utility functions
def detect_repository_language(repository_path: str) -> str:
    """
    Identifies the primary programming language of a given repository by checking file extensions.
    """
    logging.info("Detecting repository language.")
    
    java_files = ['.java', 'pom.xml', 'build.gradle']
    python_files = ['.py', 'requirements.txt', 'Pipfile', 'pyproject.toml']
    go_files = ['.go', 'go.mod', 'Gopkg.toml']
    nodejs_files = ['.js', 'package.json', 'yarn.lock']

    java_count = python_count = go_count = nodejs_count = 0
    
    for root, dirs, files in os.walk(repository_path):
        for file in files:
            if any(file.endswith(ext) for ext in java_files):
                java_count += 1
            elif any(file.endswith(ext) for ext in python_files):
                python_count += 1
            elif any(file.endswith(ext) for ext in go_files):
                go_count += 1
            elif any(file.endswith(ext) for ext in nodejs_files):
                nodejs_count += 1

    if java_count >= max(python_count, go_count, nodejs_count):
        return "java"
    elif python_count >= max(java_count, go_count, nodejs_count):
        return "python"
    elif go_count >= max(java_count, python_count, nodejs_count):
        return "go"
    else:
        return "nodejs"

def find_file_in_repository(repository_path, file_name):
    """Searches for a file in the repository and returns its path if found."""
    file_path = os.path.join(repository_path, file_name)
    if os.path.exists(file_path):
        logging.info(f"File '{file_name}' found in repository: {repository_path}")
        return file_path
    else:
        logging.warning(f"File '{file_name}' NOT found in repository: {repository_path}")
        return None

def does_file_contain_string(repo_path, file_name, search_string):
    """Checks if a file contains a specific string (case-insensitive, ignoring comments)."""
    file_path = os.path.join(repo_path, file_name)
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        content = '\n'.join([line.lower() for line in content.split('\n') if not line.strip().startswith('#')])
        return search_string.lower() in content and 'USE_MASH_JAVA_OPTIONS'.lower() not in content
    except FileNotFoundError:
        return False

def does_file_contain_regex(repo_path, file_name, regex):
    """Checks if a file contains text matching a regex pattern."""
    file_path = os.path.join(repo_path, file_name)
    try:
        with open(file_path, 'r', encoding="utf-8") as file:
            content = file.read()
        content = '\n'.join([line for line in content.split('\n') if not line.strip().startswith('#')])
        return bool(re.search(regex, content, re.IGNORECASE))
    except Exception as e:
        logging.error(f"Error reading file at {file_path}: {e}")
        return False

def read_file(filepath):
    """Reads and returns the content of a file."""
    with open(filepath, 'r') as file:
        return file.read()

def read_top_level_comments(file_path):
    """Reads and returns top-level comments from a file."""
    top_level_comments = ''
    top_level_comments_exist = False
    with open(file_path, "r") as file:
        for line in file.readlines():
            top_level_comments = top_level_comments + line
            if line.startswith('---'):
                top_level_comments_exist = True
                break
    return top_level_comments if top_level_comments_exist is True else ''

def read_yaml_with_empty_lines(dir, file_name):
    """Reads YAML file while preserving comments and formatting."""
    file_path = os.path.join(dir, file_name)
    with open(file_path, 'r') as file:
        yaml = ruamel.yaml.YAML()
        yaml.preserve_quotes = True
        yaml.width = 1000
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        yaml.allow_duplicate_keys = True
        return yaml.load(file)

def write_yaml_with_empty_lines(dir, file_name, data):
    """Writes YAML file while preserving comments and formatting."""
    file_path = os.path.join(dir, file_name)
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.default_flow_style = False
    yaml.allow_duplicate_keys = True
    with open(file_path, 'w') as file:
        yaml.dump(data, file)

def extract_values_case_insensitive(data, keys):
    """Recursively extract values for the given keys in a case-insensitive way from a nested YAML structure."""
    extracted_values = {}

    def search_keys(yaml_data):
        """Recursively search for the keys in the YAML structure, handling dicts and lists."""
        if isinstance(yaml_data, dict):
            for yaml_key, value in yaml_data.items():
                yaml_key_str = str(yaml_key)  # Convert key to string
                for key in keys:
                    if yaml_key_str.lower().strip() == key.lower().strip():  # Case-insensitive match
                        extracted_values[key] = value
                search_keys(value)  # Recursively search in nested dictionaries
        elif isinstance(yaml_data, list):
            for item in yaml_data:  # Handle lists of dictionaries
                search_keys(item)

    search_keys(data)
    return extracted_values

def delete_keys_matching_pattern(data, pattern):
    """Recursively delete keys matching the given regex pattern while preserving comments."""
    if isinstance(data, dict):
        keys_to_delete = [key for key in data.keys() if isinstance(key, str) and re.match(pattern, key, re.IGNORECASE)]
        
        for key in keys_to_delete:
            comment = data.ca.items.get(key, None)  # Preserve comments
            data.pop(key)  # Remove the key
            
            # If there are preserved comments, attach them to the last remaining key
            if comment and data:
                last_key = list(data.keys())[-1]
                data.ca.items[last_key] = data.ca.items.get(last_key, []) + comment

        for key in list(data.keys()):
            delete_keys_matching_pattern(data[key], pattern)  # Recurse into nested structures

    elif isinstance(data, list):
        for item in data:
            delete_keys_matching_pattern(item, pattern)

def log_and_exit(message, log_level):
    """Logs a message at the specified log level and exits the function."""
    if log_level == 'debug':
        print('DEBUG:', message)
        logging.debug(message)
    elif log_level == 'info':
        print('INFO:', message)
        logging.info(message)
    elif log_level == 'warn':
        print('WARN:', message)
        logging.warning(message)
    elif log_level == 'error':
        print('ERROR:', message)
        logging.error(message)
    else:
        print("Invalid log level:", log_level)
    return

def find_deployment_type(root):
    """Returns the deployment type from the Bogiefile."""
    return root['environments'][0]['gear']

def find_allowlisted_gears(gears, element):
    """Find all elements from the yaml that match the gear pattern."""
    filtered_envs = []
    if 'environments' in element:
        for env in element['environments']:
            if any(gear in env['gear'] for gear in gears):
                logging.info(f"Match found: {env['gear']}")
                filtered_envs.append(env)
    return filtered_envs

def contains_key_value_pair(key, value, root):
    """Returns True if the root contains the key:value pair, else False."""
    for _key in root.keys():
        if _key.strip().upper() == key.strip().upper() and root[_key] == value.strip().split(' ')[0]:
            return True
    return False

def contains_key(key, element):
    """Returns True if the element contains the key regardless of value, else False."""
    for _key in element.keys():
        if _key.strip().upper() == key.strip().upper():
            return True
    return False

def add_key_value_pair(pos, key, value, root, comment: Optional[str] = None):
    """Adds a new key-value pair (and optional comment) to the element."""
    root.insert(pos, key, value, comment)

def update_key_value_pair(key, new_value, root, comment: Optional[str] = None):
    """Updates a key-value pair (and optional comment) in the element."""
    if comment is not None:
        root[key] = new_value + ' # ' + comment
    else:
        root[key] = new_value

def delete_keys(regex, root):
    """Delete keys matching the regex and preserve their comments."""
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

def build_mandatory_tags(data):
    """Builds mandatory tags from Bogiefile vars."""
    return {'asv': data['vars']['asv'], 'ba': data['vars']['ba'], 'component': data['vars']['component']}

def write_standard_file(file_path, lines):
    """Writes content to a file."""
    with open(file_path, 'w') as f:
        f.writelines(lines)

def normalize_whitespace(content):
    """Normalizes whitespace in content."""
    return '\n'.join(line.rstrip() for line in content.strip().splitlines())

def format_java_opts(java_opts_str):
    """Formats JAVA_OPTS with proper line breaks."""
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

def process_java_opts(obj):
    """Processes JAVA_OPTS in YAML data for proper formatting."""
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

def process_policy(obj):
    """Processes policy in YAML data for proper formatting."""
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

def get_runtime(env):
    """Extracts and validates the runtime version from environment."""
    runtime = ''
    languages = ['python', 'nodejs', 'java']
    node_runtimes = ['16', '18', '20', '22']
    java_runtimes = ['11', '17', '21']
    python_runtimes = ['3.8', '3.9', '3.10', '3.11']

    if 'runtime' in env['inputs']:
        runtime = env['inputs']['runtime']
        for lang in languages:
            if lang in runtime:
                version = runtime[len(lang):].replace('.x', '')
                if lang == 'nodejs' and version in node_runtimes:
                    return f'{lang}{version}'
                elif lang == 'java' and version in java_runtimes:
                    return f'{lang}{version}'
                elif lang == 'python' and version in python_runtimes:
                    return f'{lang}{version}'
    return None

def check_handler(env):
    """Checks and updates Python handler format if needed."""
    if 'inputs' in env and 'handler' in env['inputs']:
        handler = env['inputs']['handler']
        if '/' in handler:
            env['inputs']['handler'] = handler.replace('/', '.')

def check_docker_image_type(file_path):
    """Determines the type of Docker image from the Dockerfile."""
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

def does_dockerfile_contains_otel_supported_image(file_path):
    """Checks if Dockerfile contains a supported APM image."""
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

def omit_newrelic_vars_from_dockerfile(file_path):
    """Removes NewRelic-related lines from Dockerfile."""
    final_lines = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if ('newrelic_' in line.lower() or 'newrelic.' in line.lower() or 'new_relic' in line.lower()) and not line.startswith('#'):
                continue
            final_lines.append(line)
    return final_lines if len(final_lines) < len(lines) else []

def check_prerequisites_and_return_image_type(repository_path: str = '.'):
    """Checks repository prerequisites and returns the Docker image type."""
    if not os.path.isdir(repository_path):
        return None

    repository_language = detect_repository_language(repository_path)

    if find_file_in_repository(repository_path, "Bogiefile") is None:
        return None

    if does_file_contain_string(repository_path, "Bogiefile", "OTEL_ENABLED: true"):
        return None
    
    # if not (does_file_contain_string(repository_path, "Bogiefile", "newrelic") or 
    #         does_file_contain_string(repository_path, "Bogiefile", "NEWRELIC") or 
    #         does_file_contain_string(repository_path, "Dockerfile", "newrelic") or 
    #         does_file_contain_string(repository_path, "Dockerfile", "NEWRELIC")):
    #     return None

    dockerfile_path = find_file_in_repository(repository_path, "Dockerfile")
    if dockerfile_path:
        return check_docker_image_type(dockerfile_path)
    # return None

def upsert_mandatory_tags(pos, root, key, tags):
    resource_attributes=''
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

    if resources_attributes_updated == True:
        resource_attributes = resource_attributes[:-1]
        if is_quoted:
            resource_attributes = '"'+resource_attributes+'"'
        add_key_value_pair(pos, key, resource_attributes, root)
           
    return resources_attributes_updated

# Java-specific functions
def process_dockerfile_lines(endpoint, asv, ba, component, write_type, file_path, add_java_opts_if_missing=False):
    """Processes Dockerfile lines for OpenTelemetry instrumentation."""
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

def process_for_ecs(env, image_type, mandatory_tags):
    """Processes ECS environment for OpenTelemetry instrumentation."""
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

def process_for_fargate(env, mandatory_tags):
    """Processes Fargate environment for OpenTelemetry instrumentation."""
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
                
                # Configure logging
                if 'application_configuration' in env['inputs'] and 'logging' in env['inputs']['application_configuration']:
                    logging_config = env['inputs']['application_configuration']['logging']
                    if 'otel_collector' not in logging_config:
                        pos = int(len(logging_config.keys()) / 2)
                        add_key_value_pair(pos, 'otel_collector', 'otelservices-<lob>', logging_config, 'Directs the traces to the LOB gateway')
                        BOGIEFILE_CONTENT_UPDATED = True
                
                # Check regions
                if 'regions' in env:
                    for region in env['regions']:
                        if 'application_configuration' in region and 'logging' in region['application_configuration']:
                            logging_config = region['application_configuration']['logging']
                            if 'otel_collector' not in logging_config:
                                pos = int(len(logging_config.keys()) / 2)
                                add_key_value_pair(pos, 'otel_collector', 'otelservices-<lob>', logging_config, 'Directs the traces to the LOB gateway')
                                BOGIEFILE_CONTENT_UPDATED = True
                
                # Process Java options
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
                
                # Add OTEL_SERVICE_NAME if missing
                if 'OTEL_SERVICE_NAME' not in fargate_container_env:
                    add_key_value_pair(pos + 1, 'OTEL_SERVICE_NAME', '<YOUR SERVICE NAME>', fargate_container_env, 'Replace with your service name')
                    BOGIEFILE_CONTENT_UPDATED = True
                
                # Update mandatory tags and remove NewRelic
                if delete_keys('NEWRELIC', fargate_container_env) or upsert_mandatory_tags(pos+1, fargate_container_env, 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags):
                    BOGIEFILE_CONTENT_UPDATED = True
    
    return BOGIEFILE_CONTENT_UPDATED

def process_for_lambda(env, mandatory_tags, runtime_version):
    #pull runtime
    #
    account_number = ''
    otel_layer_arn = ''
    layer_region = ''
    arch = ''
    arn_num= ''
    print(runtime_version)
    # layer_type = 'agent' if 'java' in runtime_version else 'proto'
    if runtime_version is None:
        print("Error: runtime_version is None. Defaulting layer_type to 'proto'.")
        return False
    else:
        layer_type = 'agent' if 'java' in runtime_version else 'proto'
    AWS_LAMBDA_EXEC_WRAPPER = '' #set conditionally based on runtime
    C1_OTEL_GATEWAY_ENDPOINT=''#set conditionally based on runtime
    
    architecture = env['inputs']['architecture'] if 'architecture' in env['inputs'] else 'x86'
    print(architecture)
    
    #determin account number and endpoint (prod/non-prod)
    if 'name' in env:
        if 'prod' in env['name']:
            print('Prod layer')
            account_number = '011108305656'
            C1_OTEL_GATEWAY_ENDPOINT = 'https://otelservices.cloud.capitalone.com:9990'
            arn_num= '3'
            
        else:
            print('Non-Prod layer')
            account_number = '237724329014'
            C1_OTEL_GATEWAY_ENDPOINT = 'https://otelservices.clouddqt.capitalone.com:9990'
            if 'arm' in architecture:
                arn_num = '4' #arm
            else:
                arn_num = '6' #x86
            
    
    print('Processing for Lambda')
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

            if 'environment_variables' in region:
                if 'python' in get_runtime(env):
                    exec_wrapper = '/opt/otel-instrument'
                elif 'java' in get_runtime(env):
                    exec_wrapper = '/opt/otel-handler'
                elif 'nodejs' in get_runtime(env):
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
               
                pos = int(len(region['environment_variables'].keys()) / 2)
                for key, value in env_vars.items():
                    if key not in region['environment_variables']:
                        add_key_value_pair(pos, key, value, region['environment_variables'])
                        pos += 1  # Increment position for each new key-value pair
                        BOGIEFILE_CONTENT_UPDATED = True
                if delete_keys('NEW_RELIC', region['environment_variables']) or  upsert_mandatory_tags(pos+1, region['environment_variables'], 'OTEL_RESOURCE_ATTRIBUTES', mandatory_tags) :
                    BOGIEFILE_CONTENT_UPDATED = True
    return BOGIEFILE_CONTENT_UPDATED 

# remove unused vars from bogiefile function
def process_bogiefile_lines(endpoint, asv, ba, component, image_type, file_path):
    """Processes Bogiefile for OpenTelemetry instrumentation."""
    try:
        data = read_yaml_with_empty_lines('.', 'Bogiefile')
        BOGIEFILE_CONTENT_UPDATED = False
        filtered_envs = find_allowlisted_gears(ALLOWLISTED_GEARS, data)
        
        mandatory_tags = {}
        mandatory_tags['asv'] = data['vars'].get('asv', '<YOUR_ASV>')
        mandatory_tags['ba'] = data['vars'].get('ba', '<YOUR_BA>')
        mandatory_tags['component'] = data['vars'].get('component', '<YOUR_COMPONENT>')
        
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

# Node.js specific functions
def modify_dockerfile_node(repo_path, file_name, extracted_values):
    """
    Modify the Dockerfile by adding OpenTelemetry instrumentation setup for Node.js.

    :param repo_path: Path to the repository containing the Dockerfile.
    :param file_name: Name of the Dockerfile.
    :param extracted_values: Dictionary containing extracted values for ASV, BA, and COMPONENT.
    """
    try: 
        dockerfile_path = os.path.join(repo_path, file_name)
        
        with open(dockerfile_path, "r") as file:
            lines = file.readlines()

        # Extract values safely, defaulting to an empty string if not found
        asv_value = extracted_values.get("asv", "")
        ba_value = extracted_values.get("ba", "")
        component_value = extracted_values.get("component", "")
        url_value = extracted_values.get("flavor", "")

        # Determine the correct OTEL endpoint using regex
        if re.match(r"^(devnav/docker|docker)$", url_value):
            endpoint = "<your-endpoint>"
        elif re.match(r"^(ecs-fargate|container/fargate-api)$", url_value):
            endpoint = "http://localhost:4318"
        elif re.match(r"^(autocruise|ecs-ec2)$", url_value):
            endpoint = "http://172.17.0.1:4318"
        else:
            endpoint = "<your-endpoint>"

        # Check if required lines are already present
        npm_install_present = any("npm install @opentelemetry" in line for line in lines)
        otel_exports_present = any("OTEL_TRACES_EXPORTER" in line for line in lines)

        if npm_install_present and otel_exports_present:
            print("Dockerfile already contains the required lines. No changes made.")
            return False

        modified_lines = []
        workdir_found = False
        npm_added = False

        for line in lines:
            modified_lines.append(line)

            # Ensure a newline after WORKDIR
            if line.strip().startswith("WORKDIR"):
                modified_lines.append("\n")  # Add a blank line after WORKDIR
                workdir_found = True

            if workdir_found and not npm_install_present:
                modified_lines.append(NPM_INSTALL_COMMAND)  # Add npm install
                npm_added = True
                workdir_found = False  # Prevent duplicate insertions

            if npm_added and not otel_exports_present:
                # Fill in the template with actual values
                otel_exports_filled = OTEL_EXPORTS_TEMPLATE.format(
                    asv=asv_value, ba=ba_value, component=component_value, endpoint=endpoint
                )
                modified_lines.append("\n" + otel_exports_filled)  # Add export variables
                npm_added = False

        with open(dockerfile_path, "w") as file:
            file.writelines(modified_lines)

        print("Dockerfile updated successfully!")
        return True
    except Exception as e:
        print(f"An error occurred in modify_dockerfile: {e}")
        return False

# Python-specific functions
def add_otel_service_name(data):
    """Adds OTEL_SERVICE_NAME only if container_env/ container? exists, with an inline comment."""
    try:
        # Ensure 'environments' exists and is a list
        if "environments" not in data or not isinstance(data["environments"], list):
            print("No 'environments' section found or it's not a list.")
            return

        for env in data["environments"]:
            # Ensure 'inputs' exists and has 'container_env/container?'
            if "inputs" in env and isinstance(env["inputs"], dict) and "container_env" in env["inputs"]:
                container_env = env["inputs"]["container_env"]
                
                # Ensure 'container_env' is a dictionary
                if isinstance(container_env, dict) and "OTEL_SERVICE_NAME" not in container_env:
                    container_env["OTEL_SERVICE_NAME"] = "<your-app-name>"

                    # Add an inline comment
                    container_env.yaml_add_eol_comment("Change this to the name of your application", "OTEL_SERVICE_NAME")

    except Exception as e:
        print(f"An error occurred in add_otel_service_name: {e}")

def load_dockerfile(dockerfile_path):
    """Reads the Dockerfile content if it exists."""
    try:
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, "r") as file:
                return file.readlines()
        return []
    except (OSError, IOError) as e:
        print(f"Error reading Dockerfile: {e}")
        return []

def remove_unwanted_lines(dockerfile_content, env_vars):
    """Removes existing OTEL environment variables and 'pip install newrelic'."""
    try:
        return [
            line for line in dockerfile_content
            if "pip install newrelic" not in line and not any(line.startswith(env.split("=")[0]) for env in env_vars)
        ]
    except Exception as e:
        print(f"Error in remove_unwanted_lines: {e}")
        return dockerfile_content  # Return the unmodified content if an error occurs

def update_cmd_instruction(dockerfile_content):
    """Modifies CMD to remove 'newrelic-admin run-program' and prepend 'opentelemetry-instrument'."""
    try:
        for i, line in enumerate(dockerfile_content):
            stripped_line = line.strip()
            if stripped_line.startswith("CMD"):
                try:
                    cmd_parts = json.loads(stripped_line[4:].strip())  # Extract CMD arguments
                    
                    if isinstance(cmd_parts, list) and len(cmd_parts) > 2:
                        if cmd_parts[0] == "newrelic-admin" and cmd_parts[1] == "run-program":
                            cmd_parts = cmd_parts[2:]  # Remove "newrelic-admin" and "run-program"

                    # Ensure OpenTelemetry is prepended
                    if cmd_parts and cmd_parts[0] != "opentelemetry-instrument":
                        cmd_parts.insert(0, "opentelemetry-instrument")

                    dockerfile_content[i] = f'CMD {json.dumps(cmd_parts)}\n'

                except json.JSONDecodeError as json_error:
                    print(f"JSON parsing error in update_cmd_instruction: {json_error}")
                    pass  # Skip modification if CMD is not in expected JSON format

        return dockerfile_content
    except Exception as e:
        print(f"Error in update_cmd_instruction: {e}")
        return dockerfile_content  # Return the unmodified content if an error occurs​

def find_last_pip_install_index(dockerfile_content):
    """Finds the index of the last 'pip install' command."""
    try:
        last_pip_index = -1
        for i, line in enumerate(dockerfile_content):
            if line.strip().startswith("RUN pip install"):
                last_pip_index = i
        return last_pip_index
    except Exception as e:
        print(f"Error in find_last_pip_install_index: {e}")
        return -1  # Return -1 if an error occurs

def find_cmd_index(dockerfile_content):
    """Finds the index of the CMD instruction."""
    try:
        for i, line in enumerate(dockerfile_content):
            if line.strip().startswith("CMD"):
                return i
        return -1  # Return -1 if no CMD is found
    except Exception as e:
        print(f"Error in find_cmd_index: {e}")
        return -1  # Return -1 if an error occurs

def ensure_opentelemetry_installed(dockerfile_content):
    """Ensures OpenTelemetry installation commands are added without duplicates."""
    try:
        otel_install_cmd_distro = "RUN pip install opentelemetry-distro\n"
        otel_install_cmd_otlp = "RUN pip install opentelemetry-exporter-otlp\n"
        otel_bootstrap_cmd = "RUN opentelemetry-bootstrap -a install\n"

        # Check if individual OpenTelemetry install commands already exist
        has_distro = any("pip install opentelemetry-distro" in line for line in dockerfile_content)
        has_otlp = any("pip install opentelemetry-exporter-otlp" in line for line in dockerfile_content)
        has_bootstrap = any(otel_bootstrap_cmd.strip() in line for line in dockerfile_content)

        # If all commands exist, return unchanged content
        if has_distro and has_otlp and has_bootstrap:
            return dockerfile_content  

        # Find insertion points
        last_pip_index = find_last_pip_install_index(dockerfile_content)
        cmd_index = find_cmd_index(dockerfile_content)

        if last_pip_index != -1:
            # Insert after last 'pip install'
            insert_index = last_pip_index + 1
        elif cmd_index != -1:
            # Insert before CMD if no pip install is found
            insert_index = cmd_index
        else:
            # Insert at the end if no CMD or pip install exists
            insert_index = len(dockerfile_content)

        # Insert commands only if they are missing
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
        print(f"Error in ensure_opentelemetry_installed: {e}")
        return dockerfile_content  # Return unmodified content on failure

def determine_insert_position(dockerfile_content):
    """Finds the best position to insert ENV variables safely."""
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
            return last_env_index + 1  # Place right after last ENV statement
        if cmd_entrypoint_index != -1:
            return cmd_entrypoint_index  # Place before CMD/ENTRYPOINT
        return len(dockerfile_content)  # Default: append at the end

    except Exception as e:
        print(f"Error in determine_insert_position: {e}")
        return len(dockerfile_content)  # Fallback: append at the end

def format_env_variables(env_vars, extracted_values):
    """Formats environment variables by replacing placeholders with extracted values."""
    try:
        extracted_values = {key: extracted_values.get(key, "") for key in ["asv", "ba", "component"]}
        return [env.format(**extracted_values) + "\n" for env in env_vars] + ["\n"]
    except KeyError as e:
        print(f"KeyError: Missing key {e} in extracted_values.")
        return []
    except Exception as e:
        print(f"Unexpected error in format_env_variables: {e}")
        return []

def write_dockerfile(dockerfile_path, dockerfile_content):
    """Writes the modified content back to the Dockerfile."""
    try:
        with open(dockerfile_path, "w") as file:
            file.writelines(dockerfile_content)
        print(f"Successfully updated Dockerfile: {dockerfile_path}")
    except (OSError, IOError) as e:
        print(f"Error writing to Dockerfile {dockerfile_path}: {e}")
    except Exception as e:
        print(f"Unexpected error in write_dockerfile: {e}")

def add_env_to_dockerfile(repository_path, dockerfile_name, env_vars, extracted_values):
    """
    Adds environment variables to the Dockerfile, removes 'pip install newrelic', 
    modifies CMD to remove 'newrelic-admin run-program', and ensures OpenTelemetry installation.
    """
    dockerfile_path = os.path.join(repository_path, dockerfile_name)

    try:
        # Load Dockerfile
        dockerfile_content = load_dockerfile(dockerfile_path)
        if not dockerfile_content:
            print(f"Warning: {dockerfile_name} is empty or not found.")
            return

        # Remove unwanted lines
        dockerfile_content = remove_unwanted_lines(dockerfile_content, env_vars)

        # Modify CMD instruction
        dockerfile_content = update_cmd_instruction(dockerfile_content)

        # Ensure OpenTelemetry is installed correctly
        dockerfile_content = ensure_opentelemetry_installed(dockerfile_content)

        # Get formatted ENV variables
        formatted_env_vars = format_env_variables(env_vars, extracted_values)

        # Determine where to insert ENV variables
        insert_index = determine_insert_position(dockerfile_content)

        # Insert ENV variables at the best position
        dockerfile_content[insert_index:insert_index] = formatted_env_vars

        # Write changes to the Dockerfile
        write_dockerfile(dockerfile_path, dockerfile_content)

        print(f"Updated {dockerfile_name}:")
        print(f"  - Added environment variables at position {insert_index}.")
        print(f"  - Removed 'pip install newrelic' if it was present.")
        print(f"  - Modified CMD to remove 'newrelic-admin run-program' if found.")
        print(f"  - Ensured OpenTelemetry installation commands are correctly added.")

    except (OSError, IOError) as e:
        print(f"Error processing {dockerfile_name}: {e}")
    except Exception as e:
        print(f"Unexpected error in {dockerfile_name}: {e}")

def remove_newrelic_requirements(repo_path, filename):
    """Removes lines containing 'newrelic==' from the given file."""
    file_path = os.path.join(repo_path, filename)
    
    try:
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        with open(file_path, 'w') as file:
            for line in lines:
                if not re.match(r'^newrelic==', line.strip()):
                    file.write(line)
                    
        print(f"Processed file: {file_path}")
    
    except (OSError, IOError) as e:
        print(f"Error handling file {file_path}: {e}")

def write_bogiefile(repository_path, data, top_level_comments):
    try:
        yaml = ruamel.yaml.YAML()
        # Preserve all formatting and comments
        yaml.preserve_quotes = True
        yaml.width = 1000
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        yaml.allow_duplicate_keys = True
        
        # This is crucial for preserving anchors and references
        yaml.representer.ignore_aliases = lambda data: (
            False if hasattr(data, 'anchor') and data.anchor else True
        )

        process_java_opts(data)
        process_policy(data)
        
        # To prevent file expansion, we'll write in a specific way
        with open('./Bogiefile', 'w') as file:
            # Write top level comments first
            if top_level_comments:
                file.write(top_level_comments)
                if not top_level_comments.endswith('\n'):
                    file.write('\n')
            
            # Then dump the YAML content
            yaml.dump(data, file)
            
        print('success')
        return True
        
    except Exception as e:
        print(f"An error occurred in write_bogiefile: {e}")
        return False     

# Main processing functions
def process_java_repository(repository_path: str = '.'):
    """Processes a Java repository for OpenTelemetry instrumentation."""
    try:
        data = read_yaml_with_empty_lines('.', 'Bogiefile')
        
        endpoint = 'http://localhost:4317' if find_deployment_type(data) == 'ecs-fargate:^1' else 'http://172.17.0.1:4317'
        asv = data['vars'].get('asv', '<YOUR_ASV>')
        ba = data['vars'].get('ba', '<YOUR_BA>')
        component = data['vars'].get('component', '<YOUR_COMPONENT>')
        # flavor = data.pipeline.flavor

        if find_deployment_type(data) == 'aws-lambda:^4':
            process_bogiefile_lines(None, asv, ba, component, None, 'Bogiefile' )
        else:
            image_type = check_prerequisites_and_return_image_type(repository_path)
            if not image_type:
                logging.info("Skipping repository - prerequisites not met")
                return
            
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
            
            # Handle Dockerfile updates for APM images
            if does_dockerfile_contains_otel_supported_image('Dockerfile'):
                lines = omit_newrelic_vars_from_dockerfile('Dockerfile')
                if lines:
                    with open('Dockerfile', 'w') as file:
                        file.writelines(lines)
        
        logging.info("Migration completed successfully")
    except Exception as e:
        logging.error(f"An error occurred during migration: {e}")
        raise

def process_node_repository(repository_path: str = '.'):
    """Processes a Node.js repository for OpenTelemetry instrumentation."""
    try:
        logging.info(f"Processing local repository at: {repository_path}")

        if not os.path.isdir(repository_path):
            logging.error(f"Invalid repository path: {repository_path}")
            return

        # Verify presence of 'Bogiefile'
        if find_file_in_repository(repository_path, "Bogiefile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Bogiefile' not found", "info")
            return
        
        # Verify presence of 'Dockerfile'
        if find_file_in_repository(repository_path, "Dockerfile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Dockerfile' not found", "info")
            return
        
        # Read top level comments
        top_level_comments = read_top_level_comments("Bogiefile")
        data = read_yaml_with_empty_lines(repository_path, "Bogiefile")
        extracted_values = extract_values_case_insensitive(data, ["asv", "ba", "component", "flavor"])
        print(extracted_values)
        delete_keys_matching_pattern(data, NEW_RELIC_PATTERN)
        print('##########')
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
        bogiefile_yaml = stream.getvalue()
        bogiefile_yaml = f"{top_level_comments}{bogiefile_yaml}"
        with open('./Bogiefile', 'w') as file:
            file.write(bogiefile_yaml)
        print('success')

        # Dockerfile add lines
        modify_dockerfile_node(repository_path, "Dockerfile", extracted_values)
            
        log_and_exit(f"Successfully processed nodejs repository: {repository_path}", "info")
    except Exception as e:
        print(f"An error occurred in process_repository_directory: {e}")

def process_python_repository(repository_path: str = '.'):
    """Processes a Python repository for OpenTelemetry instrumentation."""
    try:
        logging.info(f"Processing local repository at: {repository_path}")

        if not os.path.isdir(repository_path):
            logging.error(f"Invalid repository path: {repository_path}")
            return

        # Verify presence of 'Bogiefile'
        if find_file_in_repository(repository_path, "Bogiefile") is None:
            log_and_exit(f"Skipping {repository_path} - 'Bogiefile' not found", "info")
            return

        # Verify presence of 'Dockerfile'
        # if find_file_in_repository(repository_path, "Dockerfile") is None:
        #     log_and_exit(f"Skipping {repository_path} - 'Dockerfile' not found", "info")
        #     return
        
        # Ensure 'Bogiefile' and Dockerfile contains "NEWRELIC", exit
        if (does_file_contain_string(repository_path, "Bogiefile", "newrelic") == True and 
            does_file_contain_string(repository_path, "Bogiefile", "NEWRELIC") == True and 
            does_file_contain_string(repository_path, "Dockerfile", "newrelic") == True and 
            does_file_contain_string(repository_path, "Dockerfile", "NEWRELIC") == True):
            return 
    
        process_bogiefile_lines("NA", "asv", "ba", "component", "ecs-fargate:^1", "Bogiefile")

        # Read top level comments
        top_level_comments = read_top_level_comments("Bogiefile")
        data = read_yaml_with_empty_lines(repository_path, "Bogiefile")
        extracted_values = extract_values_case_insensitive(data, ["asv", "ba", "component"])
        print(extracted_values)
        delete_keys_matching_pattern(data, NEW_RELIC_PATTERN)
        # Add OTEL_SERVICE_NAME inside container_env
        add_otel_service_name(data)
        write_bogiefile(repository_path, data, top_level_comments)
        print('success')
        # add env in dockerfile
        add_env_to_dockerfile(repository_path, "Dockerfile", PYTHON_ENVIRONMENT_VARIABLES, extracted_values)
        # remove newrelic in requirements file
        remove_newrelic_requirements(repository_path, 'requirements.txt')
            
        log_and_exit(f"Successfully processed python repository: {repository_path}", "info")
    except Exception as e:
        print(f"An error occurred in process_repository_directory: {e}")

def process_repository_directory(repository_path: str = '.'):
    """
    Main function to process a repository based on its language.
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

if __name__ == '__main__':
    """
    Process a repository directory cureent path.
    """
    repository_path = '.'
    process_repository_directory(repository_path)