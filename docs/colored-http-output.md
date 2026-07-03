# 🌈 Colored HTTP Output

APILeak provides advanced HTTP output visualization with colored status indicators and powerful filtering capabilities for enhanced security testing workflows.

## Overview

APILeak displays all HTTP requests with colored status indicators for instant visual feedback during scanning operations. This feature is enabled by default for all scan types and provides immediate visual feedback on request success/failure patterns.

## Status Code Colors

APILeak uses a consistent color scheme to represent different HTTP response categories:

- **`[+]` Green** - 2xx Success responses (200, 201, 204, etc.)
- **`[-]` Yellow** - 3xx Redirect responses (301, 302, 304, etc.)
- **`[*]` Gray** - 4xx Client error responses (400, 401, 403, 404, etc.)
- **`[x]` Red** - 5xx Server error responses (500, 502, 503, 504, etc.)

### Example Output
```bash
[+] HTTP Request: GET https://api.example.com/users "HTTP/1.1 200 OK"
[-] HTTP Request: GET https://api.example.com/old-endpoint "HTTP/1.1 301 MOVED PERMANENTLY"
[*] HTTP Request: GET https://api.example.com/nonexistent "HTTP/1.1 404 NOT FOUND"
[x] HTTP Request: GET https://api.example.com/broken "HTTP/1.1 500 INTERNAL SERVER ERROR"
```

## 🎨 Status Code Filtering

APILeak includes a powerful status code filtering feature that allows you to display only specific HTTP status codes during scanning. This is extremely useful for focusing on specific response types or reducing noise in the output.

### Usage
Use the `--status-code` option with any scan mode to filter HTTP output:

```bash
# Show only successful responses (200s)
python apileaks.py dir --target https://api.example.com --status-code 200

# Show only client errors (404s)
python apileaks.py dir --target https://api.example.com --status-code 404

# Show multiple specific status codes
python apileaks.py par --target https://api.example.com --status-code 200,201,404

# Show status code ranges
python apileaks.py scan --target https://api.example.com --status-code 200-299,400-499
```

### Practical Examples

The status-code filtering examples are organized into three levels: **basic uses**, **intermediate uses**, and **advanced uses**. Each example includes a title, a short description of what it does and what it's for, and a ready-to-copy command. The level rises as you combine the filter with wordlists, authentication, OWASP modules, and performance tuning.

---

#### Basic uses

A single-criterion filter on a simple command. Ideal for quickly reducing noise.

**1. Show only successful responses**

Limits the output to `2xx` codes so you can see at a glance which endpoints respond correctly.

```bash
python apileaks.py dir --target https://api.example.com --status-code 200
```

**2. Show only client errors**

Focuses the output on `404` (or other `4xx`) to review nonexistent or protected paths.

```bash
python apileaks.py dir --target https://api.example.com --status-code 404
```

**3. Show a range of codes**

Use a range to see a whole family of responses, for example all `2xx`.

```bash
python apileaks.py dir --target https://api.example.com --status-code 200-299
```

---

#### Intermediate uses

Combine the filter with wordlists, authentication, and several codes at once to steer the reconnaissance.

**1. Directory fuzzing: find valid endpoints**

Shows only successful endpoints using a custom wordlist and a random User-Agent for basic WAF evasion.

```bash
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --status-code 200-299 \
  --user-agent-random
```

**2. Directory fuzzing: authentication responses**

Focuses the output on authentication-related responses (`401,403`) while authenticating with a JWT.

```bash
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --status-code 401,403 \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**3. Parameter fuzzing: detect possible injection**

Looks for server errors (`5xx`) that might indicate parameter injection.

```bash
python apileaks.py par \
  --target https://api.example.com/search \
  --wordlist wordlists/parameters.txt \
  --status-code 500-599
```

**4. Parameter fuzzing: successful discoveries**

Focuses the output on parameters that produce successful responses (`200,201`).

```bash
python apileaks.py par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --status-code 200,201
```

---

#### Advanced uses

The filter combined with an orchestrated OWASP scan, framework detection, WAF evasion, and high-volume performance optimization.

**1. Full scan: monitor only critical responses**

During a scan with OWASP modules, show only the codes that matter most (`200,401,403,500`).

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --status-code 200,401,403,500 \
  --modules bola,auth,property
```

**2. Full scan: redirect chains and successes**

Combines mixed range syntax with framework detection and version fuzzing to follow redirects and successful responses.

```bash
python apileaks.py scan \
  --target https://api.example.com \
  --status-code 200-299,300-399 \
  --detect-framework \
  --fuzz-versions
```

**3. Combine the filter with WAF evasion**

Pairs status filtering with User-Agent rotation for stealthier reconnaissance.

```bash
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --status-code 200-299,401,403
```

**4. High-volume performance optimization**

On large-volume scans, the filter reduces output overhead; combine it with a high rate-limit to speed things up.

```bash
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/large_endpoints.txt \
  --status-code 200-299 \
  --rate-limit 50
```

### Filter Syntax

| Syntax | Description | Example |
|--------|-------------|---------|
| `200` | Single status code | Shows only 200 responses |
| `200,404` | Multiple specific codes | Shows 200 and 404 responses |
| `200-299` | Status code range | Shows all 2xx responses |
| `200,404,500-599` | Mixed syntax | Shows 200, 404, and all 5xx responses |

### Configuration Display

When using status code filtering, APILeak displays the active filter in the scan configuration:

```bash
🎯 Target: https://api.example.com
🎨 Status Code Filter: [200, 404]
⚡ Rate Limit: 10 req/sec
```

### Benefits

- **Noise Reduction**: Filter out irrelevant status codes to focus on important responses
- **Performance**: Reduce terminal output for faster scanning in CI/CD environments
- **Analysis**: Quickly identify patterns in specific response types
- **Debugging**: Focus on error responses (4xx, 5xx) for troubleshooting

### Use Cases

| Use Case | Filter | Description |
|----------|--------|-------------|
| **Valid Endpoint Discovery** | `--status-code 200-299` | Find all working endpoints |
| **Authentication Testing** | `--status-code 401,403` | Focus on auth-related responses |
| **Error Analysis** | `--status-code 500-599` | Identify server errors and potential vulnerabilities |
| **Redirect Analysis** | `--status-code 300-399` | Track redirect chains and moved resources |
| **Custom Analysis** | `--status-code 200,404,500` | Monitor specific response patterns |

## Docker Usage

### Directory Fuzzing with WAF Evasion
```bash
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-file wordlists/user_agents.txt \
  --status-code 200-299,401,403 \
  --output docker_scan
```

### Parameter Fuzzing with Custom User Agent
```bash
docker run --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/reports:/app/reports \
  apileak:latest par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "Docker Security Scanner" \
  --status-code 200,500-599 \
  --output param_scan
```

### Full Scan with Random User Agents
```bash
docker run --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/reports:/app/reports \
  apileak:latest scan \
  --config config/api_config.yaml \
  --target https://api.example.com \
  --user-agent-random \
  --status-code 200,401,403,500 \
  --output full_scan
```

## Advanced Features

### Integration with WAF Evasion
The colored HTTP output works seamlessly with APILeak's WAF evasion features:

```bash
# Combine status filtering with user agent rotation
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --user-agent-random \
  --status-code 200-299,401,403

# Use custom user agents with error analysis
python apileaks.py par \
  --target https://api.example.com/api \
  --wordlist wordlists/parameters.txt \
  --user-agent-custom "Security Scanner v2.0" \
  --status-code 500-599
```

### Performance Optimization
For high-volume scanning, use status code filtering to reduce output overhead:

```bash
# Focus only on successful discoveries
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/large_endpoints.txt \
  --status-code 200-299 \
  --rate-limit 50

# Monitor only critical errors during parameter fuzzing
python apileaks.py par \
  --target https://api.example.com/search \
  --wordlist wordlists/large_parameters.txt \
  --status-code 500-599 \
  --rate-limit 30
```

## Demo and Testing

**Demo**: Run `python examples/colored_http_requests_demo.py` to see all color codes and filtering in action.

The demo script demonstrates:
- All status code colors
- Filter functionality with different combinations
- Real HTTP requests to test endpoints
- Performance with different filter settings

## Technical Implementation

The colored HTTP output feature is implemented in the `HTTPRequestEngine` class with the following key components:

- **ANSI Color Codes**: Cross-platform terminal color support
- **Status Code Mapping**: Intelligent categorization of HTTP responses
- **Filter Logic**: Efficient filtering before output generation
- **Performance Optimization**: Minimal overhead during high-volume scanning

### Configuration Integration
The feature integrates with APILeak's configuration system:

```yaml
http_output:
  status_code_filter: [200, 401, 403, 500]
```

This allows for persistent filter settings across scan sessions and integration with configuration management systems.

---

The colored HTTP output feature enhances the APILeak user experience by providing immediate visual feedback and powerful filtering capabilities for focused security analysis.