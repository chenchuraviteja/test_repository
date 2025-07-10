# ASV Extraction Tool

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

This tool extracts **Application Service Version (ASV)** information from GitHub repositories by analyzing their `Bogiefile` contents. It also detects monitoring frameworks, logging frameworks, and other relevant metadata.

---

## 📚 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Input Format](#input-format)
- [Output](#output)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Support](#support)

---

## ✅ Prerequisites

- Python 3.8 or later
- GitHub account with repository access
- GitHub Personal Access Token with `repo` scope
- Basic command-line knowledge

---

## 🛠 Installation

### 1. Install Python

#### 🪟 Windows

1. Download Python: [https://www.python.org/downloads/](https://www.python.org/downloads/)
2. Run the installer
3. ✅ Check **"Add Python to PATH"**
4. Verify installation:

```cmd
python --version
```

#### 🍎 macOS

```bash
# Using Homebrew (recommended)
brew install python
```

Or download the installer from [python.org](https://www.python.org/downloads/macos/)

#### 🐧 Linux (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install python3 python3-pip
```

---

### 2. Set GitHub Token

#### 🔄 Temporary Setup (for current terminal session)

```bash
# macOS/Linux
export GITHUB_TOKEN="your_token_here"

# Windows CMD
set GITHUB_TOKEN=your_token_here

# Windows PowerShell
$env:GITHUB_TOKEN="your_token_here"
```

#### ♾ Permanent Setup (recommended)

##### macOS/Linux (`bash`, `zsh`)

```bash
echo 'export GITHUB_TOKEN="your_token_here"' >> ~/.bashrc
source ~/.bashrc
```

##### Windows PowerShell

```powershell
Add-Content -Path $PROFILE -Value '$env:GITHUB_TOKEN="your_token_here"'
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If you don’t have a `requirements.txt` file:

```bash
pip install pandas numpy requests ruamel.yaml tenacity
```

---

## 🚀 Usage

### 🔹 Basic Command

```bash
python asv_extractor.py -i input.csv -o output.csv
```

### 🔧 Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input` | Input CSV file path | `Repo_url.csv` |
| `-o, --output` | Output CSV file path | `asv_results.csv` |
| `-m, --max-workers` | Maximum worker threads | `15` |
| `-v, --verbose` | Enable verbose logging | `False` |

### 💡 Examples

Process default file:

```bash
python asv_extractor.py
```

Custom input/output:

```bash
python asv_extractor.py -i custom_input.csv -o custom_output.csv
```

Increase worker threads:

```bash
python asv_extractor.py -m 20
```

---

## 🧾 Input Format

Input CSV must contain a `Repository` column:

```csv
Repository
https://github.com/owner/repo1
https://github.com/owner/repo2
```

---

## 📤 Output

The generated CSV includes:

| Column | Description |
|--------|-------------|
| `Repository` | GitHub repo URL |
| `Language` | Detected programming language |
| `ASV` | Extracted ASV |
| `OTEL_YES` | OpenTelemetry detected |
| `NR_YES` | New Relic detected |
| `NO_APM` | No APM tool detected |
| `flavor` | `Bogiefile` flavor |
| `MANUAL_CASE` | Manual review flag |
| `has_newrelic` | New Relic framework |
| `has_micrometer` | Micrometer detected |
| `has_prometheus` | Prometheus detected |
| `has_aws_lambda_powertools` | AWS Lambda Powertools detected |
| `logging_frameworks` | Logging frameworks |
| `monitoring_frameworks` | Monitoring frameworks |

---

## 🧯 Troubleshooting

### ❗ Common Issues

#### GitHub API Rate Limits

- **Symptoms**: `API rate limit exceeded`
- **Fix**:
  - Use fewer threads (`-m 10`)
  - Ensure you're using a GitHub token
  - Wait — tool handles retries automatically

#### Missing Dependencies

- **Symptoms**: `ModuleNotFoundError`
- **Fix**:
  ```bash
  pip install -r requirements.txt
  ```

#### Invalid GitHub Token

- **Symptoms**: `Bad credentials` or 401
- **Fix**:
  - Ensure token is set and active
  - Validate scope: must include `repo`

#### Repository Access Errors

- **Symptoms**: 404 for existing repo
- **Fix**:
  - Confirm token has repo access
  - Check for typos in repo URLs

---

## ❓ FAQ

**Q: How do I check if my token works?**

```bash
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
```

**Q: Can I use this on private repos?**

✅ Yes — as long as your token has permission.

**Q: Why are some repos skipped?**

They may:
- Not exist
- Be private (no access)
- Be missing a `Bogiefile`

---

## 🆘 Support

- Open an [issue on GitHub](https://github.com)
- Contact the maintainers
- Use `-v` flag for debug logging

---

> **Note**: This tool is optimized for CapitalOne's internal GitHub Enterprise. For public GitHub, update `api_base_url` in the script accordingly.

---

## 📄 License

MIT License – see [`LICENSE`](LICENSE) for details.
