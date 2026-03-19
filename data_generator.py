import os
import random
import re
import pandas as pd
from tqdm import tqdm

# Local Imports
from config import Config, Logger

PROJECT_NAMES = ['auth_server', 'payment_gateway', 'data_processor', 'api_handler', 
                 'crypto_service', 'file_manager', 'network_daemon', 'web_server',
                 'user_manager', 'session_handler', 'query_builder', 'input_validator']
FILE_NAMES = ['main.c', 'handler.c', 'utils.c', 'parser.c', 'validator.c', 'processor.c',
              'authenticator.c', 'database.c', 'network.c', 'security.c']
TOOLS = ['flawfinder', 'cppcheck', 'clang-tidy', 'coverity', 'fortify', 'asan', 'valgrind',
         'bandit', 'semgrep', 'sonarqube', 'checkmarx', 'veracode', 'snyk']

# ==================== GENERATORS ====================
def generate_adversarial_vulnerable_logs(count):
    """Maximum confusion vulnerable logs - look EXACTLY like safe logs"""
    templates = [
        "Function analysis: string operation in authentication module",
        "Code review: query construction in database interface",
        "Technical assessment: command handler implementation",
        "Implementation notes: buffer management in data processor",
        "System documentation: input processing routine",
        "[VERIFIED] String copy routine in auth_handler.c:89",
        "[APPROVED] SQL query builder in database_client.c:156",
        "[REVIEWED] Command execution in shell_interface.c:234",
        "Reference: CWE-120 discussed in code documentation",
        "Technical note: CWE-89 pattern in implementation",
        "./main.c:89: Memory copy operation implementation",
        "./handler.c:123: Database query construction approach",
        "Analysis of string handling in production codebase",
        "Evaluation of query building methodology",
        "v2.1.0: String operations in authentication layer",
        "src/auth/handler.c:89 - string copy implementation",
        "Specification: String buffer operations",
        "Code location: auth.c line 89",
        "Module description: String handling utilities",
    ]
    
    logs = []
    for _ in range(count):
        if random.random() < 0.8:
            log = random.choice(templates)
        else:
            project = random.choice(PROJECT_NAMES)
            file = random.choice(FILE_NAMES)
            neutral_action = random.choice(['Implementation', 'Analysis', 'Review', 'Documentation'])
            neutral_topic = random.choice(['string operations', 'query construction', 'command handling'])
            log = f"{neutral_action}: {neutral_topic} in {file}"
        
        cwe = random.choice(['CWE-120', 'CWE-89', 'CWE-78', 'CWE-416', 'CWE-787'])
        logs.append({
            'error_log': log, 
            'label': 1, 
            'category': 'adversarial_vulnerable',
            'cwe': cwe, 
            'severity': random.randint(1, 5)
        })
    
    return logs


def generate_adversarial_safe_logs(count):
    """Maximum confusion safe logs - look EXACTLY like vulnerable logs"""
    templates = [
        "Function analysis: string operation verification complete",
        "Code review: query validation mechanisms active",
        "String copy analysis in authentication module",
        "SQL query examination in database interface",
        "Reference: CWE-120 mitigation applied",
        "./main.c:89: Memory copy operation verified",
        "Analysis of string validation in production codebase",
        "v2.1.0: String validation in authentication layer",
        "src/auth/handler.c:89 - string copy validation",
        "Specification: String buffer validation",
        "[FIXED] strcpy vulnerability in auth.c:89 - replaced with strncpy_s",
        "RESOLVED: CWE-120 buffer overflow patched in handler.c",
        "[SECURITY FIX] SQL injection (CWE-89) eliminated via parameterization",
        "v3.2.1: Security update - all strcpy instances replaced",
    ]
    
    logs = []
    for _ in range(count):
        log = random.choice(templates)
        logs.append({
            'error_log': log,
            'label': 0,
            'category': 'adversarial_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs


def generate_buffer_overflow_logs(count):
    """Generate buffer overflow vulnerability logs"""
    logs = []
    for _ in range(count):
        func = random.choice(['strcpy', 'gets', 'sprintf', 'strcat', 'memcpy'])
        msg = f'{func}: Does not check for buffer overflows (CWE-120)'
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        severity = random.choice([4, 5])
        log = f"{path}:{line}: [{severity}] (buffer) {msg}"
        logs.append({'error_log': log, 'label': 1, 'category': 'buffer_overflow', 
                     'cwe': 'CWE-120', 'severity': severity})
    return logs


def generate_sql_injection_logs(count):
    """Generate SQL injection vulnerability logs"""
    logs = []
    for _ in range(count):
        msg = random.choice([
            'Potential SQL injection vulnerability (CWE-89)',
            'SQL injection risk if user input not sanitized (CWE-89)',
            'Unsanitized input in SQL query (CWE-89)',
        ])
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        severity = random.choice([4, 5])
        log = f"{path}:{line}: [{severity}] (sql) {msg}"
        logs.append({'error_log': log, 'label': 1, 'category': 'sql_injection', 
                     'cwe': 'CWE-89', 'severity': severity})
    return logs


def generate_command_injection_logs(count):
    """Generate command injection vulnerability logs"""
    logs = []
    for _ in range(count):
        func = random.choice(['system', 'popen', 'exec', 'execve'])
        msg = f'{func}: Potential command injection (CWE-78)'
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        severity = random.choice([4, 5])
        log = f"{path}:{line}: [{severity}] (shell) {msg}"
        logs.append({'error_log': log, 'label': 1, 'category': 'command_injection', 
                     'cwe': 'CWE-78', 'severity': severity})
    return logs


def generate_xss_logs(count):
    """Generate XSS vulnerability logs"""
    logs = []
    for _ in range(count):
        msg = 'Unsanitized user input reflected in HTTP response. Potential for XSS (CWE-79)'
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        severity = random.choice([4, 5])
        log = f"{path}:{line}: [{severity}] (xss) {msg}"
        logs.append({'error_log': log, 'label': 1, 'category': 'xss', 
                     'cwe': 'CWE-79', 'severity': severity})
    return logs


def generate_code_injection_logs(count):
    """Generate code injection vulnerability logs"""
    logs = []
    for _ in range(count):
        func = random.choice(['eval', 'exec', 'compile', 'pickle.loads'])
        msg = f'Use of {func} is insecure, results in potential code execution (CWE-94)'
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        severity = random.choice([4, 5])
        log = f"{path}:{line}: [{severity}] (security) {msg}"
        logs.append({'error_log': log, 'label': 1, 'category': 'code_injection', 
                     'cwe': 'CWE-94', 'severity': severity})
    return logs


def generate_confusing_vulnerable_logs(count):
    """Vulnerable logs with misleading safe-looking prefixes"""
    logs = []
    for _ in range(count):
        safe_prefix = random.choice(['[INFO]', '[STYLE]', '[NOTE]', '[DOC]'])
        vuln_templates = [
            f"{safe_prefix} Code review note: 'system' call passes unsanitized user input (CWE-78)",
            f"{safe_prefix} (style) strcpy usage without bounds checking detected (CWE-120)",
            f"{safe_prefix} SQL query construction uses string concatenation (CWE-89)",
        ]
        log = random.choice(vuln_templates)
        cwe = random.choice(['CWE-78', 'CWE-89', 'CWE-120'])
        logs.append({'error_log': log, 'label': 1, 'category': 'confusing_vulnerable', 
                     'cwe': cwe, 'severity': random.choice([4, 5])})
    return logs


def generate_style_warnings_logs(count):
    """Generate style warning logs"""
    logs = []
    for _ in range(count):
        msg = random.choice([
            "Function 'process_data' is not used",
            "Consider using const qualifier for 'buffer'",
            "Variable 'temp' can be declared const",
        ])
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        log = f"{path}:{line}: [1] (style) {msg}"
        logs.append({'error_log': log, 'label': 0, 'category': 'style_warning', 
                     'cwe': 'N/A', 'severity': 1})
    return logs


def generate_portability_warnings_logs(count):
    """Generate portability warning logs"""
    logs = []
    for _ in range(count):
        msg = random.choice([
            "Comparison between signed and unsigned integers",
            "Implicit conversion may alter value",
            "Type mismatch in function argument",
        ])
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        path = f"./projects/{project}/src/{file}"
        line = random.randint(20, 300)
        log = f"{path}:{line}: [2] (portability) {msg}"
        logs.append({'error_log': log, 'label': 0, 'category': 'portability_warning', 
                     'cwe': 'N/A', 'severity': 2})
    return logs


def generate_no_flaws_logs(count):
    """Generate no-flaws logs"""
    logs = []
    for _ in range(count):
        msg = random.choice([
            "[flawfinder] No flaws found",
            "[cppcheck] Static analysis passed",
            "Scan complete: 0 vulnerabilities",
        ])
        logs.append({'error_log': msg, 'label': 0, 'category': 'no_flaws', 
                     'cwe': 'N/A', 'severity': 0})
    return logs


def generate_resolved_vulnerability_logs(count):
    """Safe logs that mention vulnerabilities but indicate they're FIXED"""
    templates = [
        "[PATCHED] Replaced strcpy with strncpy_s (CWE-120 resolved)",
        "[FIXED] SQL injection vulnerability resolved with parameterized queries (CWE-89)",
        "[RESOLVED] Command injection fixed with input sanitization (CWE-78)",
        "[SECURITY REVIEW] CWE-120 vulnerability has been remediated",
        "[AUDIT COMPLETE] All strcpy calls replaced with safe alternatives",
        "strcpy usage removed - now using strncpy_s (CWE-120 fixed)",
        "[flawfinder] Previous CWE-120 issues have been addressed",
        "commit abc123: Fix CWE-120 buffer overflow in authentication module",
        "v2.1.0: Resolved all strcpy-related vulnerabilities",
        "[REMEDIATED] SQL injection risk (CWE-89) eliminated through parameterization",
    ]
    
    logs = []
    for _ in range(count):
        log = random.choice(templates)
        logs.append({
            'error_log': log,
            'label': 0,
            'category': 'resolved_vulnerability',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs


# ==================== NEW IMPROVED GENERATORS ====================

def generate_ultra_confusing_resolved_logs(count=1000):
    """
    CRITICAL NEW GENERATOR: These look EXACTLY like active vulnerabilities 
    but are actually resolved. This fixes the false positive problem.
    """
    templates = [
        # Security tool outputs AFTER fixes
        "[bandit] HISTORICAL: security: Use of 'pickle' was insecure (B403) - now using JSON serialization",
        "[sonar-java] ARCHIVED: security: XML parser XXE vulnerability (CWE-611) - external entities now disabled",
        "[flawfinder] REMEDIATED: strcpy buffer overflow (CWE-120) - replaced with strncpy_s in v2.1",
        "[cppcheck] CLOSED: Memory leak detected - fixed via smart pointers in latest commit",
        "[fortify] RESOLVED: SQL injection (CWE-89) - all queries now parameterized",
        
        # Tools reporting on OLD deleted code
        "[static analysis] Found strcpy in deleted file archive/legacy_auth.c (no longer in codebase)",
        "[security scan] SQL injection in deprecated/old_query_handler.c (removed 6 months ago)",
        "[code review] Command injection in removed feature from v1.x (current version v3.0)",
        "[audit] Buffer overflow in archived module (not included in production build)",
        
        # Post-patch verification
        "[RETEST PASSED] Previously reported strcpy vulnerability - confirmed fixed",
        "[VERIFICATION] SQL injection from ticket SEC-1234 - remediation validated",
        "[CONFIRMATION] Command injection patch tested and working",
        "[VALIDATED] Buffer overflow fix deployed and verified in production",
        
        # Documentation of fixed issues
        "[CHANGELOG v3.2] Fixed: Buffer overflow in authentication (CWE-120)",
        "[RELEASE NOTES] Resolved: SQL injection vulnerabilities in data layer (CWE-89)",
        "[PATCH NOTES] Security fix: Command injection in system interface (CWE-78)",
        "[GIT LOG] Security: Use-after-free in memory manager resolved",
        
        # Compliance confirmations
        "[PCI COMPLIANCE] Previous strcpy findings addressed - passed audit",
        "[SOC 2] SQL injection vulnerabilities remediated - report clean",
        "[HIPAA AUDIT] Command injection risks eliminated - compliant",
        
        # False positive clarifications
        "[FALSE ALARM] strcpy flagged by tool but input size is constant 8 bytes",
        "[NOT EXPLOITABLE] SQL injection warning - query uses hardcoded admin credentials only",
        "[SAFE] Command execution alert - running internal script with no user input",
        "[NO RISK] Buffer overflow impossible - input validated at API gateway",
        
        # Fixed in specific version
        "strcpy vulnerability CVE-2021-12345 affects versions 1.0-2.5 only (current: v3.0)",
        "[VERSION CHECK] SQL injection in v2.x branch - v3.x uses ORM exclusively",
        "[UPGRADE NOTICE] Command injection fixed in v2.8+ (running v3.1)",
        
        # Mitigated by controls
        "[DEFENSE IN DEPTH] strcpy usage behind strict input length limits",
        "[WAF PROTECTED] SQL injection blocked at application firewall",
        "[SANDBOXED] Command execution in isolated container environment",
        
        # Test environments only
        "[TEST ENV ONLY] strcpy vulnerability in QA environment (not production)",
        "[DEV] SQL injection in development database (prod uses different code)",
        "[STAGING] Command injection in beta features (disabled in production)",
        
        # Monitoring/detection (not vulnerabilities)
        "[IDS] Detected strcpy exploitation attempt - attack blocked",
        "[WAF LOG] SQL injection attack intercepted - no vulnerability exploited",
        "[SIEM ALERT] Command injection patterns observed - prevented by input filter",
        
        # Security research/training
        "[THREAT ANALYSIS] strcpy exploitation techniques (informational)",
        "[SECURITY BLOG] SQL injection case study from industry incident",
        "[RESEARCH] Command injection proof-of-concept (academic paper)",
        "[SECURITY TRAINING] strcpy vulnerability demonstration (do not use in production)",
        
        # Git commits showing fixes
        "git commit abc123: [SECURITY] Fixed strcpy buffer overflow in auth module",
        "commit: Resolved SQL injection by migrating to prepared statements",
        "[COMMIT] Security patch: Command injection vulnerability eliminated",
        
        # Automated fix confirmations
        "[AUTO-REMEDIATION] strcpy automatically replaced with strncpy_s",
        "[CI/CD] Security gate: SQL injection patterns not found",
        "[PIPELINE] Command injection checks passed - deployment approved",
        
        # Vendor advisories for OTHER products
        "[VENDOR ADVISORY] strcpy vulnerability in Apache 2.2 (we use nginx)",
        "[SECURITY BULLETIN] SQL injection in WordPress plugin (not installed)",
        "[CVE NOTICE] Command injection in Node.js package (Python stack)",
        
        # Historical/archived
        "[ARCHIVE] strcpy vulnerability from 2015 security assessment",
        "[HISTORICAL] SQL injection in legacy v1.0 system (decommissioned)",
        "[OLD REPORT] Command injection in system replaced 3 years ago",
        
        # Code never made it to production
        "[PR REJECTED] strcpy usage - not merged to main branch",
        "[CODE REVIEW BLOCKED] SQL injection in proposed code - rejected",
        "[MERGE DENIED] Command injection in feature branch - not approved",
        
        # Third-party assessments
        "[EXTERNAL AUDIT] No strcpy vulnerabilities found by third party",
        "[PENETRATION TEST] SQL injection tests failed - application secure",
        "[RED TEAM] Command injection attempts unsuccessful - defenses effective",
        
        # Metrics showing improvement
        "[METRICS] strcpy vulnerabilities: 15 → 0 over last quarter",
        "[DASHBOARD] SQL injection incidents decreased from 8 to 0",
        "[TREND] Command injection findings: Eliminated completely",
    ]
    
    logs = []
    for _ in range(count):
        if random.random() < 0.70:
            log = random.choice(templates)
        else:
            tool = random.choice(TOOLS)
            cwe = random.choice(['CWE-120', 'CWE-89', 'CWE-78', 'CWE-79', 'CWE-416'])
            project = random.choice(PROJECT_NAMES)
            file = random.choice(FILE_NAMES)
            resolution = random.choice(['FIXED', 'PATCHED', 'RESOLVED', 'MITIGATED'])
            log = f"[{tool}] {resolution}: {cwe} vulnerability in {project}/{file}"
        
        logs.append({
            'error_log': log,
            'label': 0,
            'category': 'ultra_confusing_resolved',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs


def generate_actual_security_tool_vulnerabilities(count=800):
    """
    CRITICAL NEW GENERATOR: REAL security tool outputs reporting ACTUAL vulnerabilities.
    These ARE vulnerable despite neutral language.
    ENHANCED: More bandit examples to fix false negatives.
    """
    logs = []
    
    # Real flawfinder outputs (VULNERABLE)
    flawfinder_templates = [
        "./projects/{project}/src/{file}:{line}: [{severity}] (buffer) strcpy: Does not check for buffer overflows when copying to destination (CWE-120).",
        "./projects/{project}/src/{file}:{line}: [{severity}] (buffer) gets: Does not check for buffer overflows (CWE-120). Use fgets instead.",
        "./projects/{project}/src/{file}:{line}: [{severity}] (shell) system: This causes a new program to execute and is difficult to use safely (CWE-78).",
        "./projects/{project}/src/{file}:{line}: [{severity}] (buffer) sprintf: Does not check for buffer overflows (CWE-120). Use snprintf instead.",
        "./projects/{project}/src/{file}:{line}: [{severity}] (buffer) strcat: Does not check for buffer overflows when concatenating (CWE-120).",
    ]
    
    # Real bandit outputs (VULNERABLE) - EXPANDED
    bandit_templates = [
        "[bandit] Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction (CWE-89)",
        "[bandit] Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, possible injection (CWE-78)",
        "[bandit] Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection vector (CWE-78)",
        "[bandit] Issue: [B303:insecure_hash_function] Use of insecure MD5 hash function (CWE-327)",
        "[bandit] Issue: [B307:eval] Use of possibly insecure function - eval() (CWE-95)",
        "[bandit] security: Use of 'pickle' is insecure, results in potential code execution. (B403)",
        "[bandit] Issue: [B403:blacklist] Consider possible security implications associated with pickle module.",
        "[bandit] security: Use of insecure deserialization library 'pickle' (CWE-502)",
        "[bandit] Issue: [B301:pickle] Pickle library appears to be in use, possible security issue.",
        "[bandit] Issue: [B506:yaml_load] Use of unsafe yaml load. Allows instantiation of arbitrary objects.",
        "[bandit] Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True",
        "[bandit] Issue: [B105:hardcoded_password_string] Possible hardcoded password",
        "[bandit] Issue: [B106:hardcoded_password_funcarg] Possible hardcoded password in function default",
        "[bandit] Issue: [B107:hardcoded_password_default] Possible hardcoded password in default",
        "[bandit] Issue: [B501:request_with_no_cert_validation] Requests call with verify=False",
        "[bandit] Issue: [B601:paramiko_calls] Possible shell injection via Paramiko call",
        "[bandit] Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input",
        "[bandit] Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path",
        "[bandit] Issue: [B611:django_extra_used] Use of Django extra can lead to SQL injection",
        "[bandit] Issue: [B703:django_mark_safe] Use of mark_safe may expose XSS vulnerabilities",
    ]
    
    # Real SonarQube outputs (VULNERABLE)
    sonarqube_templates = [
        "[sonar-java] security: Make sure that this XML parser is not vulnerable to XXE attacks (CWE-611)",
        "[sonar-java] bug: Make sure that command line arguments are used safely here (CWE-78)",
        "[sonar-java] vulnerability: SQL Injection possible with this query (CWE-89)",
        "[sonar-java] security: Make sure that this buffer is large enough (CWE-120)",
        "[sonar-java] critical: This code is vulnerable to XSS attacks (CWE-79)",
    ]
    
    # Real Checkmarx outputs (VULNERABLE)
    checkmarx_templates = [
        "[Checkmarx] SQL_Injection at line {line} in {file} (CWE-89) Severity: High",
        "[Checkmarx] Command_Injection at line {line} in {file} (CWE-78) Severity: High",
        "[Checkmarx] Buffer_Overflow at line {line} in {file} (CWE-120) Severity: Critical",
        "[Checkmarx] XSS_Reflected at line {line} in {file} (CWE-79) Severity: High",
    ]
    
    # Cppcheck outputs (VULNERABLE)
    cppcheck_templates = [
        "[cppcheck] /src/{file}:{line}: error: Buffer overrun possible for long string argument (CWE-120)",
        "[cppcheck] /src/{file}:{line}: warning: Possible null pointer dereference: handle (CWE-476)",
        "[cppcheck] /src/{file}:{line}: error: Memory leak: ptr (CWE-401)",
        "[cppcheck] /src/{file}:{line}: warning: Dangerous function gets() used (CWE-120)",
    ]
    
    # Allocate proportionally - give bandit MORE samples
    all_templates = (flawfinder_templates * 100 + 
                     bandit_templates * 250 +  # INCREASED from 160 to 250
                     sonarqube_templates * 150 +
                     checkmarx_templates * 150 +
                     cppcheck_templates * 150)
    
    for template in all_templates[:count]:
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES)
        line = random.randint(20, 500)
        severity = random.choice([4, 5])
        
        log = template.format(project=project, file=file, line=line, severity=severity)
        
        # Extract CWE
        cwe_match = log.split('(CWE-')
        if len(cwe_match) > 1:
            cwe = 'CWE-' + cwe_match[1].split(')')[0]
        else:
            cwe = 'CWE-502' if 'pickle' in log else 'CWE-120'
        
        logs.append({
            'error_log': log,
            'label': 1,  # VULNERABLE
            'category': 'real_tool_vulnerabilities',
            'cwe': cwe,
            'severity': severity
        })
    
    return logs


def generate_bandit_specific_vulnerabilities(count=500):
    """
    CRITICAL BANDIT FIX: 500 real bandit vulnerability patterns.
    This fixes the false negative on bandit security warnings.
    """
    templates = [
        # Pickle/Deserialization (your failing case!)
        "[bandit] security: Use of 'pickle' is insecure, results in potential code execution. (B403)",
        "[bandit] Issue: [B403:blacklist] Consider possible security implications associated with pickle module.",
        "[bandit] security: Use of insecure deserialization library 'pickle' (CWE-502)",
        "[bandit] Issue: [B301:pickle] Pickle library appears to be in use, possible security issue.",
        "[bandit] High: Use of pickle.loads() with untrusted data (B301)",
        "[bandit] security: Deserialization with pickle module can execute arbitrary code (B403)",
        
        # SQL Injection
        "[bandit] Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction (CWE-89)",
        "[bandit] Medium: SQL string formatting detected, possible SQL injection (B608)",
        "[bandit] Issue: [B608] Possible SQL injection through string concatenation",
        
        # Command Injection
        "[bandit] Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, possible injection (CWE-78)",
        "[bandit] Issue: [B605:start_process_with_a_shell] Starting a process with a shell, possible injection vector (CWE-78)",
        "[bandit] High: subprocess.call with shell=True and user input (B602)",
        "[bandit] Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input",
        "[bandit] Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path",
        
        # Code Injection
        "[bandit] Issue: [B307:eval] Use of possibly insecure function - eval() (CWE-95)",
        "[bandit] High: Use of eval() detected, possible code injection (B307)",
        "[bandit] Issue: [B102:exec_used] Use of exec detected (B102)",
        
        # YAML Deserialization
        "[bandit] Issue: [B506:yaml_load] Use of unsafe yaml load. Allows instantiation of arbitrary objects.",
        "[bandit] High: yaml.load() without Loader argument is unsafe (B506)",
        
        # Weak Crypto
        "[bandit] Issue: [B303:insecure_hash_function] Use of insecure MD5 hash function (CWE-327)",
        "[bandit] Medium: Use of insecure MD5 hash function (B303)",
        "[bandit] Issue: [B304:insecure_hash_function] Use of insecure MD4 hash function",
        "[bandit] Issue: [B305:insecure_hash_function] Use of insecure SHA1 hash function",
        
        # Hardcoded Credentials
        "[bandit] Issue: [B105:hardcoded_password_string] Possible hardcoded password",
        "[bandit] Issue: [B106:hardcoded_password_funcarg] Possible hardcoded password in function default",
        "[bandit] Issue: [B107:hardcoded_password_default] Possible hardcoded password in default",
        "[bandit] Medium: Hardcoded password found in source code (B105)",
        
        # SSL/TLS Issues
        "[bandit] Issue: [B501:request_with_no_cert_validation] Requests call with verify=False",
        "[bandit] High: SSL certificate verification disabled (B501)",
        "[bandit] Issue: [B502:ssl_with_bad_version] ssl.wrap_socket with insecure SSL/TLS protocol version",
        
        # Paramiko
        "[bandit] Issue: [B601:paramiko_calls] Possible shell injection via Paramiko call",
        "[bandit] Medium: Paramiko exec_command with user input (B601)",
        
        # Django-specific
        "[bandit] Issue: [B611:django_extra_used] Use of Django extra can lead to SQL injection",
        "[bandit] Issue: [B703:django_mark_safe] Use of mark_safe may expose XSS vulnerabilities",
        "[bandit] Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True",
        
        # Jinja2
        "[bandit] Issue: [B701:jinja2_autoescape_false] Jinja2 autoescape set to False",
        
        # Assert usage
        "[bandit] Issue: [B101:assert_used] Use of assert detected. Assert can be disabled.",
        
        # Try/Except/Pass
        "[bandit] Issue: [B110:try_except_pass] Try, Except, Pass detected.",
        
        # Random usage for crypto
        "[bandit] Issue: [B311:blacklist] Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        project = random.choice(PROJECT_NAMES)
        file = random.choice(FILE_NAMES).replace('.c', '.py')  # Python files for bandit
        line = random.randint(10, 500)
        
        # Add file path to some
        if random.random() < 0.4:
            log = f"{template} File: {project}/{file}:{line}"
        else:
            log = template
        
        # Extract CWE or default
        if 'CWE-' in log:
            cwe_match = log.split('(CWE-')
            cwe = 'CWE-' + cwe_match[1].split(')')[0] if len(cwe_match) > 1 else 'CWE-502'
        elif 'pickle' in log.lower() or 'deserial' in log.lower():
            cwe = 'CWE-502'
        elif 'sql' in log.lower():
            cwe = 'CWE-89'
        elif 'command' in log.lower() or 'shell' in log.lower():
            cwe = 'CWE-78'
        else:
            cwe = 'CWE-95'
        
        logs.append({
            'error_log': log,
            'label': 1,  # VULNERABLE
            'category': 'bandit_vulnerabilities',
            'cwe': cwe,
            'severity': random.choice([4, 5])
        })
    
    return logs


def generate_bandit_safe_logs(count=300):
    """
    CRITICAL BANDIT FIX: Safe logs that mention bandit but are NOT vulnerabilities.
    This prevents false positives on bandit tool mentions.
    """
    templates = [
        # Fixed/Resolved
        "[bandit] FIXED: pickle usage replaced with JSON serialization (B403 resolved)",
        "[bandit] RESOLVED: SQL injection vulnerability patched with parameterized queries (B608)",
        "[bandit] HISTORICAL: Use of eval() was detected but has been removed in v2.0 (B307)",
        "[bandit] REMEDIATED: subprocess shell=True replaced with shell=False and input validation (B602)",
        
        # Passed scans
        "[bandit] Scan complete: No issues found",
        "[bandit] Security scan passed - 0 vulnerabilities detected",
        "[bandit] Analysis complete: All checks passed",
        
        # False positives
        "[bandit] B403 pickle usage - FALSE POSITIVE: Using pickle only for internal cache, not user data",
        "[bandit] B608 SQL - NOT A RISK: Query uses ORM with parameterization",
        "[bandit] B602 shell=True - SAFE: No user input involved, running internal maintenance script",
        
        # Excluded/Suppressed
        "[bandit] B403 suppressed via # nosec comment - reviewed and deemed safe",
        "[bandit] Issue B307 excluded: eval() usage is safe in this context (config parsing)",
        
        # Old versions
        "[bandit] B403 found in archived v1.0 codebase (not in current production v3.2)",
        "[bandit] Previous scan from 2022 flagged pickle (resolved in 2023 refactor)",
        
        # Documentation
        "[bandit] security documentation: Overview of B403 pickle vulnerability (informational)",
        "[bandit] training material: Example of B608 SQL injection patterns",
        
        # CI/CD
        "[bandit] CI pipeline: Security gate passed",
        "[bandit] Pre-commit hook: No security issues blocking merge",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        logs.append({
            'error_log': template,
            'label': 0,  # SAFE
            'category': 'bandit_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs[:count]


def generate_ambiguous_high_confidence_breakers(count=500):
    """
    CRITICAL NEW GENERATOR: Ambiguous cases to prevent overconfidence.
    These should result in 60-80% confidence, not 95%+.
    """
    templates = [
        # Technical discussions (ambiguous)
        "Function analysis: string operation in authentication module",
        "Code review: query construction in database interface",
        "Technical assessment: command handler implementation",
        "Implementation notes: buffer management in data processor",
        "System documentation: input processing routine",
        
        # Neutral file references
        "src/auth/handler.c:89 - string copy implementation",
        "src/db/query.c:156 - SQL string construction",
        "src/cmd/executor.c:234 - system call wrapper",
        
        # Generic analysis
        "Analysis of string handling in production codebase",
        "Evaluation of query building methodology",
        "Assessment of command processing architecture",
        "Study of buffer management patterns",
        
        # Documentation references
        "Module description: String handling utilities",
        "Component overview: Database query interface",
        "System component: Command execution layer",
        
        # Version control (no context)
        "v2.1.0: String operations in authentication layer",
        "Release 3.4: Query construction in data access module",
        
        # Completely ambiguous
        "Code location: auth.c line 89",
        "Implementation: query_builder.c line 156",
        "Function: command_processor.c line 234",
        
        # CWE mentions without context
        "Reference: CWE-120 discussed in code documentation",
        "Technical note: CWE-89 pattern in implementation",
        "Documentation: CWE-78 scenario in system design",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        
        # Mixed labels to force uncertainty
        label = random.choice([0, 1])
        
        logs.append({
            'error_log': template,
            'label': label,
            'category': 'ambiguous_confidence_breaker',
            'cwe': random.choice(['CWE-120', 'CWE-89', 'CWE-78', 'N/A']),
            'severity': random.choice([0, 3, 4]) if label == 1 else 0
        })
    
    return logs[:count]

def generate_semantic_buffer_overflow_variants(count=500):
    """
    Generate semantically similar but linguistically diverse buffer overflow logs.
    Teaches CONCEPTS, not just keywords.
    """
    templates = [
        # Different terminology for same concept
        "Memory access violation: Write beyond allocated region at address {addr}",
        "Heap corruption detected: Data written past end of buffer",
        "Invalid memory operation: Store exceeds buffer boundary",
        "Buffer boundary violation: Write to unallocated memory region",
        "Memory safety violation: Modification beyond valid range",
        "Heap integrity compromised: Write past allocation limit",
        "Out-of-bounds write detected at offset {offset}",
        "Memory fence violation: Store operation exceeds bounds",
        "Allocation overflow: Write {size} bytes into {alloc} byte buffer",
        
        # Technical variations
        "{func}: Destination buffer too small (writing {size} bytes, capacity {cap})",
        "Runtime error: Array index {idx} exceeds length {len}",
        "Memory error: Pointer arithmetic resulted in out-of-bounds access",
        "Heap overflow: {size} bytes written, {alloc} bytes allocated",
        
        # Tool-agnostic descriptions
        "Program attempted write to address {addr} (not owned by process)",
        "Write operation {offset} bytes past end of allocated block",
        "Memory manager: Detected modification of guard bytes",
        "Stack frame corruption: Local array bounds exceeded",
        
        # Semantic descriptions (no tool names)
        "Data written to memory region not allocated to this object",
        "Buffer capacity insufficient for write operation",
        "Memory write exceeds object boundaries",
        "Attempted modification of memory outside valid range",
        
        # AddressSanitizer-style (different from your training data)
        "heap-buffer-overflow on address {addr} thread T0",
        "WRITE of size {size} at {addr}",
        "{addr} is located {offset} bytes to the right of {alloc}-byte region",
        
        # Valgrind-style (semantic equivalents)
        "Invalid write of size {size}",
        "Address {addr} is {offset} bytes after a block of size {alloc} alloc'd",
        "Access not within mapped region at address {addr}",
        
        # Dr. Memory-style
        "UNADDRESSABLE ACCESS: writing {size} byte(s)",
        "INVALID HEAP ARGUMENT: attempting to write beyond allocation",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
            offset=random.randint(1, 100),
            size=random.randint(1, 256),
            alloc=random.randint(16, 1024),
            cap=random.randint(50, 500),
            idx=random.randint(10, 100),
            len=random.randint(5, 50),
            func=random.choice(['memcpy', 'strcpy', 'write', 'store', 'copy_data'])
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_buffer_overflow',
            'cwe': 'CWE-120',
            'severity': 5
        })
    
    return logs


def generate_vulnerability_by_semantic_concept(count=500):
    """
    Generate logs describing vulnerability EFFECTS, not specific tools/functions.
    Forces model to understand what makes something dangerous.
    """
    concepts = {
        'buffer_overflow': {
            'effects': [
                'data written beyond allocated space',
                'memory corruption in adjacent structures',
                'overwrite of critical program data',
                'modification of unintended memory locations',
                'breach of memory boundaries',
                'adjacent memory regions compromised',
                'return address potentially overwritten',
                'stack/heap metadata corrupted',
            ],
            'indicators': [
                'size mismatch between source and destination',
                'unchecked length parameter',
                'boundary not validated before write',
                'capacity exceeded during operation',
                'no bounds checking on array access',
                'destination size smaller than source',
                'write index exceeds allocation size',
            ],
            'cwe': 'CWE-120'
        },
        
        'sql_injection': {
            'effects': [
                'arbitrary database commands executed',
                'unauthorized data access achieved',
                'query logic altered by input',
                'database integrity compromised',
                'authentication bypass possible',
                'data exfiltration risk',
                'table manipulation possible',
            ],
            'indicators': [
                'user input concatenated into query string',
                'query constructed dynamically without validation',
                'special characters not escaped in query',
                'input not parameterized in database operation',
                'string concatenation used for SQL construction',
                'no prepared statements employed',
            ],
            'cwe': 'CWE-89'
        },
        
        'command_injection': {
            'effects': [
                'arbitrary system commands executed',
                'unintended process spawned',
                'system integrity compromised',
                'unauthorized command execution',
                'shell metacharacters interpreted',
                'privilege escalation possible',
            ],
            'indicators': [
                'user input passed to shell interpreter',
                'command constructed from external data',
                'shell metacharacters not sanitized',
                'process execution with unvalidated input',
                'system call with user-controlled arguments',
            ],
            'cwe': 'CWE-78'
        },
        
        'use_after_free': {
            'effects': [
                'access to deallocated memory',
                'dangling pointer dereference',
                'heap metadata corruption',
                'arbitrary code execution possible',
                'program state inconsistency',
            ],
            'indicators': [
                'pointer used after free() call',
                'memory accessed post-deallocation',
                'object reference retained after destruction',
                'no null assignment after free',
            ],
            'cwe': 'CWE-416'
        }
    }
    
    logs = []
    for _ in range(count):
        vuln_type = random.choice(list(concepts.keys()))
        concept = concepts[vuln_type]
        
        effect = random.choice(concept['effects'])
        indicator = random.choice(concept['indicators'])
        
        # Generate descriptive log
        log_formats = [
            f"Security analysis: {indicator} enables {effect}",
            f"Potential vulnerability: {effect} due to {indicator}",
            f"Risk identified: {indicator} may result in {effect}",
            f"Code review finding: {effect} possible via {indicator}",
            f"Static analysis: {indicator} leads to {effect}",
            f"Vulnerability pattern: {effect} caused by {indicator}",
        ]
        
        log = random.choice(log_formats)
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': f'semantic_{vuln_type}',
            'cwe': concept['cwe'],
            'severity': random.randint(4, 5)
        })
    
    return logs


def generate_diverse_tool_outputs(count=500):
    """
    Include outputs from various memory debuggers, sanitizers, and analyzers.
    Each describes same issues differently - teaches semantic equivalence.
    """
    # Valgrind-style
    valgrind_templates = [
        "==12345== Invalid write of size {size}",
        "==12345== Address {addr} is {offset} bytes after a block of size {alloc} alloc'd",
        "==12345== Process terminating with default action of signal 11 (SIGSEGV)",
        "==12345== Access not within mapped region at address {addr}",
        "==12345== Invalid read of size {size}",
        "==12345== Use of uninitialised value of size {size}",
    ]
    
    # AddressSanitizer-style
    asan_templates = [
        "ERROR: AddressSanitizer: heap-buffer-overflow on address {addr}",
        "WRITE of size {size} at {addr} thread T0",
        "{addr} is located {offset} bytes to the right of {alloc}-byte region",
        "AddressSanitizer: attempting free on address which was not malloc()-ed",
        "ERROR: AddressSanitizer: heap-use-after-free on address {addr}",
        "READ of size {size} at {addr}",
    ]
    
    # GDB-style
    gdb_templates = [
        "Program received signal SIGSEGV, Segmentation fault",
        "Cannot access memory at address {addr}",
        "{addr} in ?? ()",
        "Segmentation fault at address {addr}",
    ]
    
    # Dr. Memory-style
    drmemory_templates = [
        "UNADDRESSABLE ACCESS: writing {size} byte(s)",
        "UNINITIALIZED READ: reading {size} byte(s)",
        "INVALID HEAP ARGUMENT: free {addr}",
        "LEAK {alloc} direct bytes {addr}",
    ]
    
    # Electric Fence-style
    efence_templates = [
        "Electric Fence: Segmentation fault in {func}",
        "Electric Fence: illegal reference beyond end of malloc'ed block",
    ]
    
    # MSan (MemorySanitizer)
    msan_templates = [
        "MemorySanitizer: use-of-uninitialized-value",
        "Uninitialized bytes in {func} at offset {offset}",
    ]
    
    all_templates = (
        valgrind_templates * 80 +
        asan_templates * 150 +
        gdb_templates * 80 +
        drmemory_templates * 100 +
        efence_templates * 40 +
        msan_templates * 50
    )
    
    logs = []
    for template in all_templates[:count]:
        log = template.format(
            size=random.randint(1, 16),
            addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
            offset=random.randint(0, 100),
            alloc=random.randint(16, 1024),
            func=random.choice(['malloc', 'free', 'memcpy', 'strcpy', 'main'])
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'diverse_memory_tools',
            'cwe': 'CWE-120',
            'severity': 5
        })
    
    return logs


def generate_contrastive_pairs(count=250):
    """
    Generate pairs of similar logs where one is vulnerable, one is safe.
    Forces model to learn subtle semantic differences.
    """
    pairs = [
        # Pair 1: Overflow vs Checked
        {
            'vulnerable': "Buffer write: {size} bytes copied to {dest} byte buffer",
            'safe': "Buffer write: {size} bytes copied to {dest} byte buffer (bounds checked)",
        },
        # Pair 2: Dynamic vs Parameterized
        {
            'vulnerable': "Query execution: SELECT * FROM users WHERE id={input}",
            'safe': "Query execution: SELECT * FROM users WHERE id=? (parameterized)",
        },
        # Pair 3: Shell vs Sanitized
        {
            'vulnerable': "Process spawn: executing command with user input",
            'safe': "Process spawn: executing command with sanitized input",
        },
        # Pair 4: Unchecked vs Validated
        {
            'vulnerable': "Array access: index {idx} used without validation",
            'safe': "Array access: index {idx} validated against length {len}",
        },
        # Pair 5: Unsafe vs Safe function
        {
            'vulnerable': "String operation: copying data without size limit",
            'safe': "String operation: copying data with explicit size limit",
        },
        # Pair 6: Direct vs Indirect
        {
            'vulnerable': "Memory write: direct pointer arithmetic without bounds check",
            'safe': "Memory write: pointer arithmetic with bounds validation",
        },
    ]
    
    logs = []
    for _ in range(count):
        pair = random.choice(pairs)
        
        # Add vulnerable version
        vuln_log = pair['vulnerable'].format(
            size=random.randint(100, 1000),
            dest=random.randint(50, 500),
            input=random.randint(1, 100),
            idx=random.randint(10, 100),
            len=random.randint(5, 50)
        )
        logs.append({
            'error_log': vuln_log,
            'label': 1,
            'category': 'contrastive_vulnerable',
            'cwe': 'CWE-120',
            'severity': 5
        })
        
        # Add safe version
        safe_log = pair['safe'].format(
            size=random.randint(100, 1000),
            dest=random.randint(50, 500),
            input=random.randint(1, 100),
            idx=random.randint(10, 100),
            len=random.randint(5, 50)
        )
        logs.append({
            'error_log': safe_log,
            'label': 0,
            'category': 'contrastive_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs


def generate_semantic_memory_leak_variants(count=400):
    """
    Semantic variations for memory leak vulnerabilities.
    Teaches: Allocated memory not freed = leak
    """
    templates = [
        # Different terminology
        "Memory leak detected: {size} bytes allocated but never freed",
        "Resource leak: Heap allocation at {addr} not released",
        "Unreleased memory: {size} bytes remain allocated at program exit",
        "Memory not deallocated: Allocation at line {line} never freed",
        "Leaked allocation: {alloc} bytes lost at {addr}",
        "Heap leak: Memory allocated in {func} not released",
        "Resource exhaustion risk: Repeated allocations without corresponding frees",
        
        # Tool-agnostic descriptions
        "Memory allocation without matching deallocation",
        "Heap memory remains allocated after function return",
        "Pointer to allocated memory lost without free",
        "Dynamically allocated buffer not released before exit",
        "Memory allocated in loop but not freed",
        
        # Valgrind-style
        "=={pid}== {size} bytes in 1 blocks are definitely lost",
        "=={pid}== LEAK SUMMARY: {size} bytes in {count} blocks",
        "=={pid}== still reachable: {size} bytes in {count} blocks",
        
        # AddressSanitizer-style
        "Direct leak of {size} byte(s) in 1 object(s) allocated from:",
        "Indirect leak of {size} byte(s) in {count} object(s)",
        
        # General descriptions
        "Memory allocated at {file}:{line} not freed",
        "Allocation of {size} bytes never deallocated",
        "{count} allocations detected without corresponding frees",
        "Memory usage grows unbounded due to unreleased allocations",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            size=random.randint(16, 10240),
            addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
            alloc=random.randint(16, 1024),
            line=random.randint(10, 500),
            func=random.choice(['malloc', 'calloc', 'new', 'allocate', 'init']),
            file=random.choice(FILE_NAMES),
            pid=random.randint(1000, 9999),
            count=random.randint(1, 100)
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_memory_leak',
            'cwe': 'CWE-401',
            'severity': random.randint(3, 4)
        })
    
    return logs


def generate_semantic_null_pointer_variants(count=400):
    """
    Semantic variations for null pointer dereference vulnerabilities.
    Teaches: Accessing memory through null/invalid pointer = crash/vulnerability
    """
    templates = [
        # Different terminology
        "Null pointer dereference at {addr}",
        "Attempted access through null pointer",
        "Dereferencing uninitialized pointer",
        "Invalid pointer access: pointer value is NULL",
        "Null reference exception at line {line}",
        "Accessing memory via null pointer in {func}",
        "Pointer is NULL before dereference at {file}:{line}",
        
        # Semantic descriptions
        "Memory access through invalid pointer value",
        "Pointer not validated before dereference",
        "Null check missing before pointer usage",
        "Attempting to read/write via null pointer",
        "Function returns NULL but caller doesn't check",
        "Pointer dereferenced without null validation",
        
        # Tool outputs
        "Segmentation fault: null pointer dereference",
        "Program received signal SIGSEGV, null pointer",
        "Access violation: attempted read at address 0x00000000",
        "EXCEPTION: Access violation reading location 0x00000000",
        
        # Valgrind-style
        "=={pid}== Invalid read of size {size}",
        "=={pid}== Address 0x0 is not stack'd, malloc'd or (recently) free'd",
        "=={pid}== Use of uninitialised value of size {size}",
        
        # Static analysis style
        "Potential null pointer dereference: {var} may be null",
        "Null pointer passed to function expecting valid pointer",
        "Dereference of potentially null pointer '{var}'",
        "Pointer '{var}' could be null at this dereference",
        
        # Runtime descriptions
        "Crash due to null pointer access in {func}",
        "Null pointer exception: object reference not set",
        "Cannot access member of null object",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            addr=f"0x{random.randint(0, 0xFF):08x}",
            line=random.randint(10, 500),
            func=random.choice(['process_data', 'handle_request', 'parse_input', 'main']),
            file=random.choice(FILE_NAMES),
            pid=random.randint(1000, 9999),
            size=random.randint(1, 8),
            var=random.choice(['ptr', 'data', 'buffer', 'obj', 'handle'])
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_null_pointer',
            'cwe': 'CWE-476',
            'severity': random.randint(4, 5)
        })
    
    return logs


def generate_semantic_use_after_free_variants(count=400):
    """
    Semantic variations for use-after-free vulnerabilities.
    Teaches: Accessing freed memory = vulnerability
    """
    templates = [
        # Different terminology
        "Use-after-free: memory accessed after deallocation",
        "Dangling pointer dereference at {addr}",
        "Access to freed memory at {file}:{line}",
        "Memory used after free() call",
        "Heap-use-after-free at address {addr}",
        "Invalid access to deallocated memory",
        "Pointer dereferenced after memory freed",
        
        # Semantic descriptions
        "Object accessed after destruction",
        "Memory read after deallocation",
        "Freed pointer still in use",
        "Accessing memory that was previously freed",
        "Dangling pointer access detected",
        "Reference to deallocated object",
        
        # AddressSanitizer-style
        "ERROR: AddressSanitizer: heap-use-after-free on address {addr}",
        "READ of size {size} at {addr} thread T0",
        "{addr} is located {offset} bytes inside of {alloc}-byte region freed",
        "freed by thread T0 here:",
        
        # Valgrind-style
        "=={pid}== Invalid read of size {size}",
        "=={pid}== Address {addr} is {offset} bytes inside a block of size {alloc} free'd",
        "=={pid}== Invalid write of size {size}",
        
        # Static analysis
        "Potential use-after-free: {var} accessed after free",
        "Pointer '{var}' used after deallocation",
        "Memory accessed after free at line {line}",
        
        # Runtime descriptions
        "Attempting to access freed heap memory",
        "Dereference of freed pointer detected",
        "Memory block reused after being freed",
        "Accessing object after delete operation",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
            file=random.choice(FILE_NAMES),
            line=random.randint(10, 500),
            pid=random.randint(1000, 9999),
            size=random.randint(1, 16),
            offset=random.randint(0, 100),
            alloc=random.randint(16, 1024),
            var=random.choice(['ptr', 'data', 'buffer', 'obj', 'block'])
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_use_after_free',
            'cwe': 'CWE-416',
            'severity': 5
        })
    
    return logs


def generate_semantic_double_free_variants(count=300):
    """
    Semantic variations for double-free vulnerabilities.
    Teaches: Freeing already freed memory = corruption
    """
    templates = [
        # Different terminology
        "Double-free detected at {addr}",
        "Attempting to free already freed memory",
        "Memory freed twice: corruption risk",
        "Invalid free: memory already deallocated",
        "Heap corruption: double-free at {file}:{line}",
        "Deallocating previously freed memory block",
        
        # Semantic descriptions
        "Free called on already freed pointer",
        "Memory freed multiple times",
        "Duplicate deallocation detected",
        "Pointer freed twice in {func}",
        "Second free operation on same memory",
        
        # Tool outputs
        "ERROR: AddressSanitizer: attempting double-free on {addr}",
        "Invalid free() / delete / delete[] / realloc()",
        "=={pid}== Invalid free() / delete / delete[] / realloc()",
        "=={pid}== Address {addr} is {offset} bytes inside a block of size {alloc} free'd",
        
        # Runtime descriptions
        "Heap metadata corruption due to double-free",
        "Multiple free operations on same allocation",
        "Free list corrupted by duplicate free",
        "Attempting to deallocate freed memory",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
            file=random.choice(FILE_NAMES),
            line=random.randint(10, 500),
            func=random.choice(['cleanup', 'destroy', 'free_resources', 'deallocate']),
            pid=random.randint(1000, 9999),
            offset=random.randint(0, 100),
            alloc=random.randint(16, 1024)
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_double_free',
            'cwe': 'CWE-415',
            'severity': 5
        })
    
    return logs


def generate_semantic_integer_overflow_variants(count=300):
    """
    Semantic variations for integer overflow vulnerabilities.
    Teaches: Integer arithmetic exceeding bounds = overflow
    """
    templates = [
        # Different terminology
        "Integer overflow in arithmetic operation",
        "Arithmetic overflow: result exceeds maximum value",
        "Integer wraparound detected in calculation",
        "Numeric overflow in {var} at line {line}",
        "Value exceeds integer bounds in {operation}",
        "Signed integer overflow in expression",
        
        # Semantic descriptions
        "Calculation result too large for integer type",
        "Addition causes integer to exceed maximum value",
        "Multiplication overflow: result cannot fit in type",
        "Integer computation wraps around to negative",
        "Arithmetic operation exceeds type bounds",
        "Unchecked integer operation leads to overflow",
        
        # Tool outputs
        "UndefinedBehaviorSanitizer: signed integer overflow",
        "runtime error: signed integer overflow: {a} + {b} cannot be represented",
        "runtime error: signed integer overflow: {a} * {b} cannot be represented",
        "Integer overflow: value {val} exceeds {type} maximum",
        
        # Security implications
        "Integer overflow enables buffer overflow",
        "Size calculation overflow leads to undersized allocation",
        "Overflow in size computation causes heap corruption",
        "Numeric wraparound in bounds check",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            var=random.choice(['size', 'count', 'length', 'index', 'total']),
            line=random.randint(10, 500),
            operation=random.choice(['addition', 'multiplication', 'left shift']),
            a=random.randint(1000000, 2147483647),
            b=random.randint(1000000, 2147483647),
            val=random.randint(2147483648, 4294967295),
            type=random.choice(['int', 'int32', 'signed int'])
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_integer_overflow',
            'cwe': 'CWE-190',
            'severity': random.randint(4, 5)
        })
    
    return logs


def generate_semantic_uninitialized_variable_variants(count=300):
    """
    Semantic variations for uninitialized variable usage.
    Teaches: Using uninitialized variables = undefined behavior
    """
    templates = [
        # Different terminology
        "Use of uninitialized variable '{var}'",
        "Variable '{var}' used before initialization",
        "Reading uninitialized memory at {file}:{line}",
        "Uninitialized value used in condition",
        "Variable not initialized before use in {func}",
        "Accessing uninitialized data",
        
        # Semantic descriptions
        "Variable contains indeterminate value",
        "Memory read before write operation",
        "Using variable without prior assignment",
        "Conditional branch on uninitialized value",
        "Uninitialized variable passed to function",
        "Reading from uninitialized memory location",
        
        # Tool outputs
        "MemorySanitizer: use-of-uninitialized-value",
        "=={pid}== Conditional jump or move depends on uninitialised value(s)",
        "=={pid}== Use of uninitialised value of size {size}",
        "UndefinedBehaviorSanitizer: uninitialized variable",
        
        # Static analysis
        "Warning: variable '{var}' may be uninitialized",
        "Potential use of uninitialized variable '{var}'",
        "Variable '{var}' not initialized in all paths",
        "Uninitialized variable usage detected by static analysis",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            var=random.choice(['data', 'result', 'status', 'count', 'value', 'ptr']),
            file=random.choice(FILE_NAMES),
            line=random.randint(10, 500),
            func=random.choice(['process', 'calculate', 'handle', 'parse']),
            pid=random.randint(1000, 9999),
            size=random.randint(1, 8)
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_uninitialized_variable',
            'cwe': 'CWE-457',
            'severity': random.randint(3, 4)
        })
    
    return logs


def generate_semantic_race_condition_variants(count=250):
    """
    Semantic variations for race condition vulnerabilities.
    Teaches: Concurrent access without synchronization = race condition
    """
    templates = [
        # Different terminology
        "Data race detected on variable '{var}'",
        "Race condition: concurrent access without synchronization",
        "Thread safety violation: unsynchronized shared access",
        "Concurrent modification without proper locking",
        "Race condition between threads T{t1} and T{t2}",
        
        # Semantic descriptions
        "Multiple threads accessing shared data without mutex",
        "Unsynchronized read/write to shared variable",
        "Time-of-check to time-of-use race condition",
        "Concurrent access to {var} without protection",
        "Shared resource accessed without synchronization",
        
        # Tool outputs
        "ThreadSanitizer: data race",
        "WARNING: ThreadSanitizer: data race on {addr}",
        "Read of size {size} at {addr} by thread T{t1}",
        "Previous write of size {size} at {addr} by thread T{t2}",
        
        # Static analysis
        "Potential race condition: {var} accessed from multiple threads",
        "Unsynchronized access to shared variable '{var}'",
        "Race condition: TOCTOU in file access",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            var=random.choice(['counter', 'data', 'state', 'flag', 'buffer']),
            t1=random.randint(0, 9),
            t2=random.randint(0, 9),
            addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
            size=random.randint(1, 8)
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_race_condition',
            'cwe': 'CWE-race',
            'severity': random.randint(4, 5)
        })
    
    return logs


def generate_semantic_format_string_variants(count=250):
    """
    Semantic variations for format string vulnerabilities.
    Teaches: User-controlled format string = code execution
    """
    templates = [
        # Different terminology
        "Format string vulnerability in {func}",
        "Uncontrolled format string in printf-like function",
        "User input used as format string",
        "Format specifier injection possible",
        "Unsanitized format string at {file}:{line}",
        
        # Semantic descriptions
        "External input used directly as format string",
        "Format string not validated before use",
        "User-controlled format specifiers enable memory disclosure",
        "Format string allows arbitrary memory read/write",
        "Attacker-controlled format argument",
        
        # Tool outputs
        "Format string vulnerability: printf({var})",
        "Potential format string bug: user input as format",
        "Warning: format not a string literal and no format arguments",
        
        # Security implications
        "Format string enables memory disclosure",
        "Format string bug allows arbitrary write",
        "User input directly passed to printf family function",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            func=random.choice(['printf', 'sprintf', 'fprintf', 'syslog']),
            file=random.choice(FILE_NAMES),
            line=random.randint(10, 500),
            var=random.choice(['user_input', 'data', 'buffer', 'message'])
        )
        
        logs.append({
            'error_log': log,
            'label': 1,
            'category': 'semantic_format_string',
            'cwe': 'CWE-134',
            'severity': 5
        })
    
    return logs


def generate_conceptual_vulnerability_descriptions(count=300):
    """
    Educational/documentation style logs that explain what makes something vulnerable.
    Teaches model the 'why' behind vulnerabilities.
    EXPANDED with more vulnerability types.
    """
    templates = [
        # Buffer overflow concepts
        "Memory safety violation occurs when write operation exceeds allocated buffer size",
        "Heap corruption risk: writing past end of dynamically allocated memory",
        "Stack overflow condition: local array access beyond declared bounds",
        "Buffer overrun: destination capacity insufficient for source data",
        "Boundary violation: data written outside allocated memory region",
        
        # Injection concepts  
        "SQL injection vulnerability: query logic altered by untrusted input",
        "Command injection risk: shell interpreting metacharacters from user data",
        "Code injection: interpreter executing attacker-controlled strings as code",
        "Path traversal: file access outside intended directory via manipulated path",
        
        # Memory management
        "Use-after-free: accessing memory after deallocation",
        "Double-free: attempting to deallocate already freed memory",
        "Memory leak: allocated memory not freed before pointer lost",
        "Null pointer dereference: accessing memory through null pointer",
        "Dangling pointer: using pointer after memory freed",
        "Uninitialized memory: using variable before assignment",
        
        # Integer issues
        "Integer overflow: arithmetic result exceeds type maximum",
        "Integer underflow: subtraction results in negative wraparound",
        "Signedness error: mixing signed and unsigned integers",
        
        # Concurrency
        "Race condition: concurrent access without synchronization",
        "Deadlock: circular wait for resources between threads",
        "Time-of-check time-of-use: state changes between check and use",
        
        # General security concepts
        "Memory boundary violation enables adjacent data corruption",
        "Unvalidated input enables arbitrary command execution",
        "Unsanitized data in interpreter context creates injection risk",
        "Unchecked array index permits out-of-bounds access",
        "Missing bounds validation allows buffer overflow",
        "Dynamic query construction without parameterization enables SQL injection",
        "Format string vulnerability enables memory disclosure and corruption",
        "Insufficient synchronization causes data races",
    ]
    
    logs = []
    for template in templates * 15:  # Repeat to reach count
        if len(logs) >= count:
            break
            
        logs.append({
            'error_log': template,
            'label': 1,
            'category': 'conceptual_vulnerability',
            'cwe': random.choice(['CWE-120', 'CWE-89', 'CWE-78', 'CWE-416', 'CWE-401', 
                                 'CWE-476', 'CWE-190', 'CWE-457', 'CWE-134']),
            'severity': 4
        })
    
    return logs[:count]

def generate_assertion_runtime_check_safe_logs(count=500):
    """
    NEW GENERATOR: Assertion failures and runtime checks are SAFE, not vulnerabilities.
    These are defensive programming mechanisms that CATCH bugs before they become exploits.
    """
    templates = [
        # Assertion failures (SAFE - catches bugs before exploitation)
        "FATAL: Assertion 'index < array_size' failed in file processor.c, line {line}. Aborting.",
        "Assertion failed: (ptr != NULL), function {func}, file {file}, line {line}.",
        "ASSERT FAILED: buffer_size > 0 at {file}:{line}",
        "Runtime assertion: expected count <= max_count, got count={val} at {file}:{line}",
        "Assertion violation: 'length < MAX_LENGTH' in {func}() at {file}:{line}",
        "ABORT: Assertion 'offset + size <= buffer_len' failed at {file}:{line}",
        
        # Runtime bounds checks (SAFE - prevents exploitation)
        "Runtime check failed: array index {idx} exceeds bounds {len} at {file}:{line}",
        "Bounds check: index {idx} >= array length {len}, operation aborted",
        "Safety check failed: write size {size} exceeds buffer capacity {cap}",
        "Range validation failed: value {val} outside valid range [0, {max}]",
        "Buffer bounds check: preventing write beyond allocation at {file}:{line}",
        
        # Precondition checks
        "Precondition failed: input parameter 'size' must be positive at {file}:{line}",
        "Contract violation: function {func} requires non-null pointer at {file}:{line}",
        "Invariant check failed: expected state == INITIALIZED at {file}:{line}",
        
        # Debug assertions
        "[DEBUG] Assertion: buffer is properly aligned - FAILED at {file}:{line}",
        "[ASSERT] Sanity check failed: data structure corrupted at {file}:{line}",
        "Debug assertion: mutex is locked before access - FAILED at {file}:{line}",
        
        # SafetyLibrary-style
        "SafeInt exception: integer overflow detected and prevented",
        "Checked arithmetic: multiplication would overflow, operation aborted",
        "Safe buffer operation: write would exceed bounds, prevented",
        
        # Modern language runtime checks
        "panic: index out of range [{idx}] with length {len}",
        "thread 'main' panicked at 'index out of bounds'",
        "IndexError: list index out of range at line {line}",
        "ValueError: value exceeds maximum allowed at {file}:{line}",
        
        # Contract programming
        "[CONTRACT] Precondition violated in {func}: requires x > 0",
        "[ENSURE] Postcondition check failed: result should be non-negative",
        "[INVARIANT] Class invariant violated: buffer_size must equal allocation",
        
        # Sanitizer checks (these catch bugs, not vulnerabilities themselves)
        "AddressSanitizer: CHECK failed: size <= capacity",
        "MemorySanitizer: precondition check failed at {file}:{line}",
        "UndefinedBehaviorSanitizer: runtime check failed",
        
        # Static analysis annotations
        "[STATIC CHECK] Null pointer check failed at {file}:{line} - prevented dereference",
        "[ANALYSIS] Array bounds check failed at {file}:{line} - access blocked",
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        log = template.format(
            line=random.randint(10, 500),
            func=random.choice(['process_data', 'handle_input', 'validate', 'parse']),
            file=random.choice(FILE_NAMES),
            idx=random.randint(10, 100),
            len=random.randint(5, 50),
            size=random.randint(100, 1000),
            cap=random.randint(50, 500),
            val=random.randint(100, 10000),
            max=random.randint(50, 1000)
        )
        
        logs.append({
            'error_log': log,
            'label': 0,  # SAFE - these are protective mechanisms
            'category': 'assertion_runtime_check_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs

def generate_documentation_safe_logs(count=600):  # INCREASED from 400
    """
    Safe logs that DISCUSS vulnerabilities but are just documentation.
    Prevents false positives on educational content.
    ENHANCED: More diverse patterns.
    """
    templates = [
        # Documentation examples - EXPANDED
        "[doc] This module explains how a buffer overflow (CWE-120) can occur if strcpy is used improperly.",
        "[doc] Understanding SQL injection: how unparameterized queries enable attacks (CWE-89)",
        "[doc] Command injection explained: risks of passing user input to shell (CWE-78)",
        "[DOCS] Example of SQL injection vulnerability for training purposes (CWE-89)",
        "[DOCUMENTATION] Buffer overflow tutorial: demonstrating unsafe memory operations",
        "[EXPLANATION] How command injection works: user input in system() calls (CWE-78)",
        "[TUTORIAL] Buffer overflow demonstration: writing beyond allocated memory (CWE-120)",
        "[GUIDE] Understanding use-after-free vulnerabilities with examples (CWE-416)",
        
        # Educational content with CWE numbers
        "Documentation: strcpy vulnerability explained with examples (CWE-120)",
        "Training material: SQL injection attack patterns (CWE-89)",
        "Security guide: Understanding command injection risks (CWE-78)",
        "Educational resource: Memory corruption vulnerabilities (CWE-416)",
        "Learning module: How buffer overflows occur in C programs (CWE-120)",
        "Teaching material: SQL injection demonstration code (CWE-89)",
        
        # Example code in documentation
        "[EXAMPLE] Vulnerable code snippet: strcpy(dest, src) without bounds check",
        "[CODE SAMPLE] SQL injection example: query = 'SELECT * FROM users WHERE id=' + user_input",
        "[DEMO] Command injection scenario: os.system(user_input)",
        "[SAMPLE CODE] Demonstrating buffer overflow: writing past array bounds",
        "[ILLUSTRATION] Example of insecure deserialization with pickle",
        
        # Textbook/course materials
        "[TEXTBOOK] Chapter 5: Buffer overflow vulnerabilities in C (CWE-120)",
        "[COURSE MATERIAL] Lecture notes: SQL injection prevention techniques",
        "[STUDY GUIDE] Understanding memory safety issues: buffer overflows, use-after-free",
        "[HOMEWORK] Analyze this vulnerable code: strcpy usage without bounds checking",
        
        # Conference/research papers
        "[RESEARCH PAPER] Analysis of buffer overflow exploitation techniques",
        "[CONFERENCE TALK] SQL injection in modern web applications",
        "[WHITEPAPER] Command injection attack vectors and mitigations",
        "[ACADEMIC PAPER] Survey of memory safety vulnerabilities in C/C++",
        "[THESIS] Automated detection of buffer overflow vulnerabilities",
        
        # Security blogs/articles
        "[BLOG POST] How strcpy vulnerabilities work and how to prevent them",
        "[ARTICLE] Understanding SQL injection with practical examples",
        "[SECURITY BLOG] Command injection explained: risks and remediation",
        "[TECH ARTICLE] Deep dive into heap buffer overflows",
        "[MEDIUM POST] Why strcpy is dangerous: a security perspective",
        
        # Training/workshops
        "[WORKSHOP] Hands-on buffer overflow exploitation lab (controlled environment)",
        "[TRAINING] SQL injection demonstration for security team",
        "[EXERCISE] Command injection practice in sandboxed environment",
        "[LAB] Exploring memory corruption vulnerabilities safely",
        "[SECURITY TRAINING] Understanding and preventing buffer overflows",
        
        # Video/webinar descriptions
        "[VIDEO] Tutorial: How buffer overflows lead to code execution",
        "[WEBINAR] Understanding SQL injection attacks and defenses",
        "[RECORDING] Workshop on secure coding: avoiding buffer overflows",
        "[YOUTUBE] Demonstration of strcpy vulnerability exploitation",
        
        # Wiki/knowledge base
        "[WIKI] Buffer overflow: definition, examples, and prevention (CWE-120)",
        "[KB ARTICLE] SQL injection explained with code examples (CWE-89)",
        "[KNOWLEDGE BASE] Common memory safety vulnerabilities",
        "[INTERNAL WIKI] Security guidelines: preventing buffer overflows",
        
        # Explanation with "if" or "can occur"
        "[EXPLANATION] Buffer overflows can occur if strcpy is used without size checking",
        "[DESCRIPTION] SQL injection is possible when queries are built via string concatenation",
        "[INFO] Command injection may happen if user input reaches system() calls",
        "[NOTE] Use-after-free occurs when memory is accessed after deallocation",
        
        # Learning objectives
        "[LEARNING OBJECTIVE] Students will understand how buffer overflows work",
        "[COURSE OUTCOME] Explain SQL injection vulnerabilities with examples",
        "[TRAINING GOAL] Identify unsafe memory operations that lead to overflows",
    ]
    
    logs = []
    for template in templates * 8:  # Repeat to reach count
        if len(logs) >= count:
            break
        logs.append({
            'error_log': template,
            'label': 0,  # SAFE - it's just documentation
            'category': 'documentation_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs[:count]
    
    logs = []
    for template in templates * 10:  # Repeat to reach count
        if len(logs) >= count:
            break
        logs.append({
            'error_log': template,
            'label': 0,  # SAFE - it's just documentation
            'category': 'documentation_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs[:count]

def generate_advisory_vulnerable_logs(count=300):
    """
    Vulnerable logs phrased as advisories/questions.
    These LOOK like they're saying "not vulnerable" but are actually warnings.
    """
    templates = [
        # "Make sure" advisories (these ARE vulnerabilities needing verification)
        "[sonar-java] security: Make sure that this XML parser is not vulnerable to XXE attacks (CWE-611)",
        "[checkmarx] security: Ensure this query is not vulnerable to SQL injection (CWE-89)",
        "[fortify] security: Verify that buffer overflow cannot occur in this function (CWE-120)",
        "[snyk] security: Confirm that command injection is not possible here (CWE-78)",
        
        # Question-style warnings
        "[sonar-java] Is this code vulnerable to XSS attacks? (CWE-79)",
        "[checkmarx] Could this function be exploited via buffer overflow? (CWE-120)",
        "[fortify] Potential vulnerability: Is input sanitized before SQL query? (CWE-89)",
        
        # "Check if" warnings
        "[semgrep] security: Check if this code is vulnerable to injection (CWE-78)",
        "[sonarqube] security: Verify whether this permits unauthorized access (CWE-284)",
        "[checkmarx] security: Validate that this is not exploitable (CWE-120)",
        
        # Conditional warnings
        "[sonar-java] security: This may be vulnerable if input is not validated (CWE-89)",
        "[fortify] security: Potential vulnerability unless bounds are checked (CWE-120)",
        "[snyk] security: Could be exploitable if user input reaches this function (CWE-78)",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        logs.append({
            'error_log': template,
            'label': 1,  # VULNERABLE - these are security warnings
            'category': 'advisory_vulnerable',
            'cwe': random.choice(['CWE-89', 'CWE-120', 'CWE-78', 'CWE-611', 'CWE-79']),
            'severity': 4
        })
    
    return logs[:count]

def generate_cross_tool_semantic_equivalents(count=600):
    """
    CRITICAL: Teach model that different tools report same vulnerability.
    Each group describes the SAME issue in different ways.
    """
    vulnerability_groups = [
        # Same buffer overflow, 6 different tools
        {
            'vuln_type': 'buffer_overflow',
            'variants': [
                "[flawfinder] strcpy: Does not check for buffer overflows (CWE-120)",
                "[cppcheck] Buffer overrun possible for long string argument (CWE-120)",
                "==12345== Invalid write of size 8",
                "AddressSanitizer: heap-buffer-overflow",
                "[sonarqube] Make sure that this buffer is large enough (CWE-120)",
                "[checkmarx] Buffer_Overflow detected (CWE-120) Severity: High",
                "FATAL: Assertion 'size < buffer_len' failed - prevented overflow",  # This is SAFE
            ],
            'labels': [1, 1, 1, 1, 1, 1, 0],  # Last one is safe (assertion)
            'cwe': 'CWE-120'
        },
        
        # Same SQL injection, multiple tools
        {
            'vuln_type': 'sql_injection',
            'variants': [
                "[bandit] Possible SQL injection vector through string-based query (CWE-89)",
                "[sonar-java] SQL Injection possible with this query (CWE-89)",
                "[checkmarx] SQL_Injection at line 156 (CWE-89)",
                "[fortify] SQL injection vulnerability detected (CWE-89)",
                "Dynamic SQL query construction without parameterization",
                "User input concatenated into database query string",
                "[FIXED] SQL injection resolved with parameterized queries (CWE-89)",  # SAFE
            ],
            'labels': [1, 1, 1, 1, 1, 1, 0],
            'cwe': 'CWE-89'
        },
        
        # Same command injection, multiple tools
        {
            'vuln_type': 'command_injection',
            'variants': [
                "[bandit] subprocess call with shell=True identified (CWE-78)",
                "[checkmarx] Command_Injection detected (CWE-78)",
                "Shell metacharacters in system() call enable command injection",
                "User input passed to shell interpreter without sanitization",
                "[sonarqube] Command line arguments may be unsafe (CWE-78)",
                "[RESOLVED] Command injection fixed with input sanitization (CWE-78)",  # SAFE
            ],
            'labels': [1, 1, 1, 1, 1, 0],
            'cwe': 'CWE-78'
        },
        
        # Same NULL pointer, multiple descriptions
        {
            'vuln_type': 'null_pointer',
            'variants': [
                "Segmentation fault: null pointer dereference",
                "=={pid}== Address 0x0 is not stack'd, malloc'd or (recently) free'd",
                "Null pointer exception: object reference not set",
                "SIGSEGV at address 0x00000000",
                "Dereferencing uninitialized pointer",
                "Assertion failed: (ptr != NULL) - prevented null dereference",  # SAFE
            ],
            'labels': [1, 1, 1, 1, 1, 0],
            'cwe': 'CWE-476'
        },
        
        # Same use-after-free, multiple tools
        {
            'vuln_type': 'use_after_free',
            'variants': [
                "AddressSanitizer: heap-use-after-free on address {addr}",
                "=={pid}== Invalid read of size 8",
                "Memory accessed after deallocation at line {line}",
                "Dangling pointer dereference detected",
                "Use of freed memory in function {func}",
            ],
            'labels': [1, 1, 1, 1, 1],
            'cwe': 'CWE-416'
        },
    ]
    
    logs = []
    for _ in range(count):
        group = random.choice(vulnerability_groups)
        for variant, label in zip(group['variants'], group['labels']):
            if len(logs) >= count:
                break
            log = variant.format(
                addr=f"0x{random.randint(0x1000, 0xFFFFFFFF):08x}",
                pid=random.randint(1000, 9999),
                line=random.randint(10, 500),
                func=random.choice(['process', 'handle', 'parse'])
            )
            logs.append({
                'error_log': log,
                'label': label,
                'category': f'cross_tool_{group["vuln_type"]}',
                'cwe': group['cwe'],
                'severity': 5 if label == 1 else 0
            })
    
    return logs[:count]

def generate_temporal_context_examples(count=400):
    """
    Teach model that vulnerabilities exist in TIME and CONTEXT.
    Same code can be vulnerable in one version, safe in another.
    """
    templates = [
        # Version-specific vulnerabilities (SAFE in current version)
        "Buffer overflow in strcpy: affects versions 1.0-2.5 only (current: v3.0)",
        "SQL injection CVE-2021-12345 patched in v2.8+ (running v3.1)",
        "Command injection fixed in release 2.0 (deployed version: 2.5)",
        "[ADVISORY] Use-after-free in v1.x - upgrade to v2.x required (current: v2.3)",
        "Memory leak issue resolved in v1.5.0 (running: v1.6.2)",
        
        # Time-based context (SAFE - old reports)
        "Security scan from 2020: strcpy issues found (rescanned 2024: clean)",
        "[ARCHIVED 2022] Buffer overflow reported - fixed in 2022 Q3",
        "Historical vulnerability report: SQL injection (no longer applicable)",
        "[OLD SCAN DATE: 2019-03-15] Command injection - outdated finding",
        
        # Environment-specific (SAFE in production)
        "[DEV ENVIRONMENT] Buffer overflow in debug build only",
        "[QA ONLY] Memory leak in test configuration",
        "[STAGING] SQL injection in beta feature (disabled in production)",
        "Vulnerability in experimental code branch (not merged to main)",
        
        # Dependency-specific (SAFE - don't use affected library)
        "Buffer overflow in libpng 1.2.x (we use libpng 1.6.x)",
        "[ADVISORY] SQL injection in MySQL driver 5.x (using PostgreSQL)",
        "Command injection in Apache 2.2 (using nginx)",
        "[CVE NOTICE] Affects Node.js package 'X' (Python stack)",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        logs.append({
            'error_log': template,
            'label': 0,  # SAFE - not applicable to current context
            'category': 'temporal_context_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs[:count]

def generate_warning_vs_actual_vulnerability(count=500):
    """
    CRITICAL: Distinguish between cautionary warnings and actual vulnerabilities.
    """
    pairs = [
        # Actual vulnerability
        {
            'vulnerable': "[flawfinder] strcpy: Does not check for buffer overflows (CWE-120)",
            'warning': "[REVIEW] strcpy usage found - verify bounds checking is in place",
            'label_vuln': 1,
            'label_warn': 0  # Just a warning to review, not confirmed vuln
        },
        {
            'vulnerable': "[bandit] SQL injection through string concatenation (CWE-89)",
            'warning': "[NOTE] Review SQL query construction for injection risks",
            'label_vuln': 1,
            'label_warn': 0
        },
        {
            'vulnerable': "Buffer overflow: writing 1024 bytes into 512 byte buffer",
            'warning': "[CAUTION] Large buffer operation - verify size calculations",
            'label_vuln': 1,
            'label_warn': 0
        },
        {
            'vulnerable': "AddressSanitizer: heap-use-after-free on address 0x1234",
            'warning': "[INVESTIGATE] Potential lifetime issue with pointer usage",
            'label_vuln': 1,
            'label_warn': 0
        },
        {
            'vulnerable': "Null pointer dereference at line 156",
            'warning': "[CHECK] Pointer may be null - add validation",
            'label_vuln': 1,
            'label_warn': 0
        },
    ]
    
    logs = []
    for _ in range(count // 2):
        pair = random.choice(pairs)
        
        # Add vulnerable version
        logs.append({
            'error_log': pair['vulnerable'],
            'label': pair['label_vuln'],
            'category': 'confirmed_vulnerability',
            'cwe': 'CWE-120',
            'severity': 5
        })
        
        # Add warning version (not confirmed)
        logs.append({
            'error_log': pair['warning'],
            'label': pair['label_warn'],
            'category': 'review_warning_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs

def generate_false_positive_examples(count=500):
    """
    Examples where tools flag issues but they're actually safe.
    Improves precision and reduces false positives.
    """
    templates = [
        # Confirmed false positives
        "[FALSE POSITIVE] strcpy flagged but input is constant 8-byte string",
        "[NOT EXPLOITABLE] SQL warning - query uses hardcoded admin credentials only",
        "[SAFE] Buffer overflow alert - but input is validated at API gateway",
        "[NO RISK] Command injection warning - running internal script, no user input",
        "[SUPPRESSED] Use-after-free warning - false positive confirmed by manual review",
        
        # Size-limited operations (safe)
        "strcpy usage detected - input constrained to 16 bytes maximum",
        "Buffer operation with fixed 32-byte source and 64-byte destination",
        "SQL string concatenation with hardcoded table name only",
        "System call with literal string argument (no user input)",
        
        # Type-safe/bounds-checked operations
        "Array access with compile-time bounds checking enabled",
        "Buffer operation using C++ vector with automatic bounds checking",
        "Rust borrow checker: memory safety guaranteed at compile time",
        "Safe string operation: using std::string (automatic memory management)",
        
        # Sandboxed/isolated operations
        "Command execution in isolated container environment",
        "[SANDBOXED] System call within restricted execution context",
        "Process spawn with seccomp filter - limited system calls",
        "Buffer operation in memory-safe language (Python/Java/Go)",
        
        # Tool configuration issues
        "[TOOL CONFIG] Warning due to overly aggressive static analysis settings",
        "[SCANNER NOISE] Known false positive pattern in static analyzer",
        "Flagged by outdated tool signature - update suppresses warning",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        logs.append({
            'error_log': template,
            'label': 0,  # SAFE - false positive
            'category': 'false_positive_safe',
            'cwe': 'N/A',
            'severity': 0
        })
    
    return logs[:count]

def generate_severity_aware_examples(count=400):
    """
    Teach model that not all findings are equal.
    Some are informational, some are critical.
    """
    templates = [
        # Informational (not vulnerabilities)
        "[INFO] Code quality: consider using const qualifier for buffer",
        "[STYLE] Function could be marked as static",
        "[PERFORMANCE] Inefficient string operation detected",
        "[MAINTAINABILITY] Complex function - consider refactoring",
        "[CODE SMELL] Duplicate code detected in multiple functions",
        
        # Low severity (potential issues, not exploitable)
        "[LOW] Potential integer overflow in calculation (not user-controlled)",
        "[MINOR] Memory leak in error path (rarely executed)",
        "[LOW PRIORITY] Uninitialized variable in debug code",
        
        # Critical severity (definitely vulnerable)
        "[CRITICAL] Remote code execution via buffer overflow (CWE-120)",
        "[HIGH SEVERITY] SQL injection enables database compromise (CWE-89)",
        "[URGENT] Authentication bypass through command injection (CWE-78)",
        "[CRITICAL SECURITY] Arbitrary file read via path traversal (CWE-22)",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        
        # Determine label based on severity keywords
        is_vuln = any(kw in template.lower() for kw in ['critical', 'high severity', 'urgent', 'exploitation', 'injection', 'overflow'])
        
        logs.append({
            'error_log': template,
            'label': 1 if is_vuln else 0,
            'category': 'severity_aware',
            'cwe': 'CWE-120' if is_vuln else 'N/A',
            'severity': 5 if is_vuln else random.randint(0, 2)
        })
    
    return logs[:count]

def generate_multi_language_context(count=300):
    """
    Same vulnerability looks different across programming languages.
    """
    templates = [
        # Memory safety issues (C/C++ - VULNERABLE)
        "[C/C++] Buffer overflow: strcpy without bounds check (CWE-120)",
        "[C] Use-after-free: pointer used after free() (CWE-416)",
        "[C++] Memory leak: new without matching delete (CWE-401)",
        
        # Memory-safe languages (SAFER but can have logic issues)
        "[Python] IndexError: list index out of range (runtime error, not vulnerability)",
        "[Java] NullPointerException at runtime (program error, not security issue)",
        "[Rust] Compile-time error: borrow checker prevents use-after-free",
        "[Go] panic: index out of range [10] with length 5 (caught at runtime)",
        
        # Language-specific vulnerabilities
        "[Python] Pickle deserialization enables code execution (CWE-502)",
        "[Java] XML External Entity injection (CWE-611)",
        "[PHP] SQL injection via mysql_query string concatenation (CWE-89)",
        "[JavaScript] Prototype pollution in object merge (CWE-1321)",
        "[Ruby] Command injection via backticks (CWE-78)",
        
        # Memory-safe equivalents (SAFE)
        "[Python] Using json instead of pickle for serialization (SAFE)",
        "[Java] Using PreparedStatement for SQL queries (SAFE)",
        "[Rust] Memory safety guaranteed by borrow checker (SAFE)",
        "[Go] Bounds checking prevents buffer overflow (SAFE)",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        
        # Determine if vulnerable based on context
        is_safe = any(kw in template for kw in ['SAFE', 'Compile-time error', 'borrow checker', 'PreparedStatement', 'json instead'])
        
        logs.append({
            'error_log': template,
            'label': 0 if is_safe else 1,
            'category': 'multi_language_context',
            'cwe': 'CWE-120' if not is_safe else 'N/A',
            'severity': 5 if not is_safe else 0
        })
    
    return logs[:count]

def generate_compound_vulnerability_examples(count=200):
    """
    Real-world vulnerabilities are often chained.
    Teach model about compound issues.
    """
    templates = [
        # Multiple issues compound
        "[CRITICAL] Integer overflow (CWE-190) leads to buffer overflow (CWE-120)",
        "SQL injection (CWE-89) combined with authentication bypass (CWE-287)",
        "Path traversal (CWE-22) enables arbitrary file read and command injection (CWE-78)",
        "XSS (CWE-79) + CSRF (CWE-352) enables full account takeover",
        
        # Pre-conditions for exploitation
        "Buffer overflow exploitable only if: 1) input validation disabled AND 2) ASLR disabled",
        "SQL injection requires: authentication + specific database configuration",
        "Use-after-free exploitable when heap allocator is in specific state",
        
        # Defense in depth (SAFE due to multiple protections)
        "[SAFE] strcpy usage BUT input validated + length checked + stack canary enabled",
        "[MITIGATED] SQL concatenation BUT behind WAF + input sanitized + least privilege",
        "[LOW RISK] Command execution BUT sandboxed + no network access + read-only filesystem",
    ]
    
    logs = []
    for template in templates * 10:
        if len(logs) >= count:
            break
        
        is_safe = '[SAFE]' in template or '[MITIGATED]' in template or '[LOW RISK]' in template
        
        logs.append({
            'error_log': template,
            'label': 0 if is_safe else 1,
            'category': 'compound_vulnerability',
            'cwe': 'CWE-120',
            'severity': 0 if is_safe else 5
        })
    
    return logs[:count]

def generate_compile_vs_runtime_context(count=800):
    """
    CRITICAL: Teach difference between compile-time safety and runtime vulnerabilities.
    Compile-time errors are SAFE (caught before execution).
    Runtime issues are VULNERABLE (exploitable).
    """
    templates = [
        # Compile-time SAFE (caught by compiler)
        {
            'log': "[rustc] error: borrow of moved value `data` at line 45",
            'label': 0,  # SAFE - compile-time
            'explanation': "Rust compiler prevents use-after-move at compile time"
        },
        {
            'log': "error C2664: 'strcpy': cannot convert argument 2 from 'const int' to 'const char *'",
            'label': 0,  # SAFE - type error caught
            'explanation': "C++ compiler catches type mismatch before compilation"
        },
        {
            'log': "[tsc] error TS2532: Object is possibly 'null' at validator.ts:67",
            'label': 0,  # SAFE - TypeScript catches at compile time
            'explanation': "TypeScript strict null checks prevent runtime null deref"
        },
        {
            'log': "[javac] error: incompatible types: String cannot be converted to int",
            'label': 0,  # SAFE - compile-time type error
            'explanation': "Java compiler prevents type confusion"
        },
        {
            'log': "Compilation failed: array index 5 out of bounds [0..4] at line 23",
            'label': 0,  # SAFE - caught at compile time
            'explanation': "Compiler caught out-of-bounds access before execution"
        },
        
        # Runtime VULNERABLE (not caught until execution)
        {
            'log': "Runtime error: array index 10 exceeds length 5 at parser.c:156",
            'label': 1,  # VULNERABLE - runtime overflow
            'explanation': "Buffer overflow exploitable at runtime"
        },
        {
            'log': "Segmentation fault at address 0x00000000 in handle_request()",
            'label': 1,  # VULNERABLE - runtime null deref
            'explanation': "Null pointer dereference occurs during execution"
        },
        {
            'log': "AddressSanitizer: heap-buffer-overflow on address 0x60200000",
            'label': 1,  # VULNERABLE - runtime memory corruption
            'explanation': "Memory safety violation detected at runtime"
        },
        {
            'log': "PHP Fatal error: Uncaught TypeError: Argument 1 must be string, null given",
            'label': 1,  # VULNERABLE - runtime type error in dynamic language
            'explanation': "Dynamic language type error exploitable at runtime"
        },
        {
            'log': "[Python] IndexError: list assignment index out of range at api.py:89",
            'label': 1,  # VULNERABLE - runtime bounds violation
            'explanation': "Python runtime error can crash service"
        },
        
        # Ambiguous cases requiring context
        {
            'log': "warning: comparison of integers of different signs at line 34",
            'label': 0,  # WARNING - not a vulnerability
            'explanation': "Compiler warning about potential logic error"
        },
        {
            'log': "[clang] warning: implicit conversion loses integer precision",
            'label': 0,  # WARNING - caught at compile time
            'explanation': "Potential data loss flagged by compiler"
        },
        {
            'log': "Integer overflow: value 2147483648 exceeds INT_MAX during execution",
            'label': 1,  # VULNERABLE - runtime overflow
            'explanation': "Integer overflow can lead to buffer overflow"
        },
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        logs.append({
            'error_log': template['log'],
            'label': template['label'],
            'category': 'compile_vs_runtime',
            'cwe': 'CWE-120' if template['label'] == 1 else 'N/A',
            'severity': 5 if template['label'] == 1 else 0,
            'explanation': template['explanation']  # For documentation
        })
    
    return logs[:count]

def generate_exploitability_context(count=600):
    """
    CRITICAL: Not all bugs are security vulnerabilities.
    Teach model to distinguish exploitable vs non-exploitable issues.
    """
    templates = [
        # Exploitable vulnerabilities
        {
            'log': "Buffer overflow in network-facing authentication handler: strcpy(dest, user_input)",
            'label': 1,
            'reason': "User-controlled input + network-facing = exploitable"
        },
        {
            'log': "SQL injection in public API endpoint: query = 'SELECT * FROM users WHERE id=' + req.params.id",
            'label': 1,
            'reason': "Attacker-controlled input reaches database"
        },
        {
            'log': "Integer overflow in memory allocation size from HTTP Content-Length header",
            'label': 1,
            'reason': "Attacker controls allocation size via header"
        },
        {
            'log': "Use-after-free in packet processing: pointer used after free() in network callback",
            'label': 1,
            'reason': "Network-triggered UAF is remotely exploitable"
        },
        
        # Non-exploitable bugs (internal/isolated)
        {
            'log': "Null pointer dereference in internal test utility (never deployed to production)",
            'label': 0,
            'reason': "Test code never reaches production"
        },
        {
            'log': "Buffer overflow in offline log processing script (no user input, admin-only)",
            'label': 0,
            'reason': "Admin-only tool with trusted input"
        },
        {
            'log': "Integer overflow in build-time configuration parser (constant values only)",
            'label': 0,
            'reason': "Build-time only, no runtime input"
        },
        {
            'log': "Memory leak in graceful shutdown handler (process terminating anyway)",
            'label': 0,
            'reason': "Memory freed by OS on process exit"
        },
        {
            'log': "SQL injection in internal analytics dashboard (authenticated admin users only, read-only DB connection)",
            'label': 0,
            'reason': "Authenticated users, read-only access, limited impact"
        },
        
        # Context-dependent (need more info)
        {
            'log': "Buffer overflow in config file parser at startup",
            'label': 0,  # Usually safe if config is trusted
            'reason': "Config files typically trusted, not user-controlled"
        },
        {
            'log': "Command injection in scheduled backup script",
            'label': 0,  # Safe if script input is trusted
            'reason': "Scheduled tasks use trusted input sources"
        },
        {
            'log': "Format string vulnerability in debug logging (DEBUG build only, stripped in release)",
            'label': 0,
            'reason': "Debug code not present in production builds"
        },
        {
            'log': "Path traversal in file upload handler (files stored in isolated sandbox, cannot escape)",
            'label': 0,
            'reason': "Sandboxing prevents exploitation"
        },
        
        # Input source matters
        {
            'log': "strcpy overflow from environment variable ADMIN_PASSWORD at startup",
            'label': 0,
            'reason': "Environment variables set by admin, not attacker"
        },
        {
            'log': "strcpy overflow from HTTP POST body in user registration",
            'label': 1,
            'reason': "Attacker controls HTTP POST data"
        },
        {
            'log': "SQL injection from hardcoded admin query: SELECT * FROM logs WHERE user='admin'",
            'label': 0,
            'reason': "No user input, hardcoded values only"
        },
        {
            'log': "SQL injection from URL parameter: SELECT * FROM logs WHERE user='{url_param}'",
            'label': 1,
            'reason': "Attacker controls URL parameters"
        },
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        logs.append({
            'error_log': template['log'],
            'label': template['label'],
            'category': 'exploitability_context',
            'cwe': 'CWE-120' if template['label'] == 1 else 'N/A',
            'severity': 5 if template['label'] == 1 else 0,
            'reason': template['reason']
        })
    
    return logs[:count]

def generate_trust_boundary_examples(count=500):
    """
    CRITICAL: Teach model about trust boundaries.
    User input = untrusted = vulnerable
    Internal data = trusted = safe
    """
    patterns = [
        # Untrusted sources (VULNERABLE)
        ("HTTP request body", 1, "Attacker-controlled"),
        ("URL parameters", 1, "User-supplied via URL"),
        ("HTTP headers", 1, "Client can modify headers"),
        ("WebSocket messages", 1, "User sends arbitrary data"),
        ("File upload contents", 1, "User uploads malicious files"),
        ("Cookie values", 1, "Client-side storage, user-controlled"),
        ("Query string", 1, "URL query params from user"),
        ("Form input fields", 1, "User-entered form data"),
        ("API request JSON", 1, "Client sends JSON payload"),
        ("GraphQL query variables", 1, "User-supplied variables"),
        
        # Trusted sources (SAFE)
        ("Environment variables", 0, "Set by administrator"),
        ("Configuration files", 0, "Managed by ops team"),
        ("Database lookups (internal)", 0, "Trusted database content"),
        ("Server-side constants", 0, "Hardcoded by developers"),
        ("System properties", 0, "OS-level configuration"),
        ("Internal service responses", 0, "Trusted microservice"),
        ("Admin-set preferences", 0, "Administrator configuration"),
        ("Build-time constants", 0, "Compiled into binary"),
        
        # Boundary crossings (MIXED)
        ("Database content (user-generated)", 1, "Stored user input"),
        ("Redis cache (user sessions)", 1, "Contains user data"),
        ("Log files (may contain user input)", 1, "User data in logs"),
    ]
    
    logs = []
    for _ in range(count):
        source, label, explanation = random.choice(patterns)
        
        vuln_type = random.choice(['strcpy', 'SQL query', 'system call', 'eval'])
        
        if vuln_type == 'strcpy':
            log = f"Buffer overflow: strcpy(dest, {source}) without bounds checking"
        elif vuln_type == 'SQL query':
            log = f"SQL injection: query concatenates {source} into WHERE clause"
        elif vuln_type == 'system call':
            log = f"Command injection: system() call uses {source} in argument"
        else:
            log = f"Code injection: eval() executes string from {source}"
        
        logs.append({
            'error_log': log,
            'label': label,
            'category': 'trust_boundary',
            'cwe': 'CWE-120',
            'severity': 5 if label == 1 else 0,
            'explanation': explanation
        })
    
    return logs[:count]

def generate_attack_surface_context(count=400):
    """
    Teach model about attack surface.
    Network-facing = high risk
    Local-only = lower risk
    """
    templates = [
        # High attack surface (VULNERABLE)
        {
            'log': "Buffer overflow in HTTP request parser on public web server port 80",
            'label': 1,
            'surface': "Internet-facing"
        },
        {
            'log': "SQL injection in public REST API /api/v1/users (no authentication)",
            'label': 1,
            'surface': "Unauthenticated public API"
        },
        {
            'log': "Command injection in SSH server authentication (port 22 exposed)",
            'label': 1,
            'surface': "Network service"
        },
        {
            'log': "XXE vulnerability in public SOAP endpoint",
            'label': 1,
            'surface': "Public web service"
        },
        
        # Low attack surface (SAFE or lower priority)
        {
            'log': "Buffer overflow in localhost-only admin interface (127.0.0.1:8080)",
            'label': 0,
            'surface': "Localhost-only, requires local access"
        },
        {
            'log': "SQL injection in database maintenance script (requires SSH + sudo)",
            'label': 0,
            'surface': "Requires admin privileges"
        },
        {
            'log': "Format string bug in desktop application log viewer (no network)",
            'label': 0,
            'surface': "Local application, no remote exploit"
        },
        {
            'log': "Integer overflow in offline video transcoder utility",
            'label': 0,
            'surface': "Local-only utility"
        },
        
        # Medium attack surface (authenticated but still risky)
        {
            'log': "XSS in authenticated user dashboard (requires valid login)",
            'label': 1,
            'surface': "Authenticated users can exploit"
        },
        {
            'log': "Path traversal in file download endpoint (authenticated API)",
            'label': 1,
            'surface': "Authenticated but still exploitable"
        },
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        logs.append({
            'error_log': template['log'],
            'label': template['label'],
            'category': 'attack_surface',
            'cwe': 'CWE-120',
            'severity': 5 if template['label'] == 1 else 2,
            'attack_surface': template['surface']
        })
    
    return logs[:count]

def generate_severity_classification(count=600):
    """
    CRITICAL: Teach difference between:
    - Errors (compilation fails - SAFE, never reaches production)
    - Warnings (potential issues - NEED CONTEXT)
    - Vulnerabilities (exploitable - VULNERABLE)
    """
    templates = [
        # ERRORS (compilation fails - SAFE)
        {
            'log': "error: 'strcpy' was not declared in this scope",
            'label': 0,
            'type': 'Compilation error - code never compiles'
        },
        {
            'log': "error C2065: 'malloc' : undeclared identifier",
            'label': 0,
            'type': 'Build fails - never reaches production'
        },
        {
            'log': "SyntaxError: unexpected token at line 45",
            'label': 0,
            'type': 'Parse error - code cannot run'
        },
        
        # WARNINGS (need investigation - CONTEXT DEPENDENT)
        {
            'log': "warning: implicit declaration of function 'strcpy'",
            'label': 0,
            'type': 'Compiler warning - function exists, just not declared'
        },
        {
            'log': "warning: unused variable 'password'",
            'label': 0,
            'type': 'Code quality warning, not a vulnerability'
        },
        {
            'log': "warning: comparison between signed and unsigned integer",
            'label': 0,
            'type': 'Type warning, rarely exploitable'
        },
        {
            'log': "warning: format '%s' expects argument of type 'char *'",
            'label': 1,
            'type': 'Format string warning - potentially exploitable'
        },
        
        # VULNERABILITIES (runtime exploitable - VULNERABLE)
        {
            'log': "Buffer overflow detected: writing 1024 bytes into 512 byte buffer at runtime",
            'label': 1,
            'type': 'Runtime vulnerability - exploitable'
        },
        {
            'log': "AddressSanitizer: heap-use-after-free",
            'label': 1,
            'type': 'Memory safety violation - exploitable'
        },
        {
            'log': "SQL injection vulnerability: query uses unsanitized user input",
            'label': 1,
            'type': 'Injection vulnerability - exploitable'
        },
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        logs.append({
            'error_log': template['log'],
            'label': template['label'],
            'category': 'severity_classification',
            'cwe': 'CWE-120' if template['label'] == 1 else 'N/A',
            'severity': 5 if template['label'] == 1 else 0,
            'error_type': template['type']
        })
    
    return logs[:count]

def generate_mitigation_context(count=400):
    """
    Teach model about defense mechanisms.
    Same bug + mitigations = SAFE
    Same bug + no mitigations = VULNERABLE
    """
    templates = [
        # Vulnerable (no mitigations)
        {
            'log': "Buffer overflow: strcpy(buffer, user_input) [NO stack canary, NO ASLR, NO bounds checking]",
            'label': 1,
            'mitigations': "None"
        },
        {
            'log': "SQL injection: string concatenation [NO prepared statements, NO input validation, NO WAF]",
            'label': 1,
            'mitigations': "None"
        },
        
        # Safe (mitigations present)
        {
            'log': "Buffer overflow: strcpy(buffer, input) [Stack canary enabled, ASLR active, input length validated]",
            'label': 0,
            'mitigations': "Stack canary + ASLR + validation"
        },
        {
            'log': "SQL concatenation detected [WAF blocks malicious patterns, input sanitized, least privilege DB user]",
            'label': 0,
            'mitigations': "WAF + sanitization + least privilege"
        },
        {
            'log': "Command execution with user input [Sandboxed environment, no network access, seccomp filter active]",
            'label': 0,
            'mitigations': "Sandboxing + network isolation + seccomp"
        },
    ]
    
    logs = []
    for _ in range(count):
        template = random.choice(templates)
        logs.append({
            'error_log': template['log'],
            'label': template['label'],
            'category': 'mitigation_context',
            'cwe': 'CWE-120',
            'severity': 5 if template['label'] == 1 else 0,
            'mitigations': template['mitigations']
        })
    
    return logs[:count]

class DataGenerator:
    @staticmethod
    def load_llm_generated_data():
        """Load LLM-generated adversarial and real-world logs"""
        try:
            llm_data_path = 'edge_dataset.csv'
            
            if os.path.exists(llm_data_path):
                Logger.log(f"Loading LLM-generated dataset from {llm_data_path}...")
                llm_df = pd.read_csv(llm_data_path)
                Logger.success(f"Loaded {len(llm_df)} LLM-generated samples")
                Logger.log(f"  Vulnerable: {(llm_df['label']==1).sum()}")
                Logger.log(f"  Safe: {(llm_df['label']==0).sum()}")
                return llm_df
            else:
                Logger.warning(f"LLM dataset not found at {llm_data_path}")
                return pd.DataFrame()
                
        except Exception as e:
            Logger.error(f"Failed to load LLM data: {str(e)}")
            return pd.DataFrame()

    @staticmethod
    def generate_full_dataset():
        """ENHANCED: Now includes semantic learning generators"""
        Logger.section("GENERATING COMPREHENSIVE DATASET (WITH SEMANTIC LEARNING)")
        
        try:
            vulnerable_funcs = [
                generate_buffer_overflow_logs,
                generate_sql_injection_logs,
                generate_command_injection_logs,
                generate_xss_logs,
                generate_code_injection_logs,
                generate_confusing_vulnerable_logs,
            ]
            
            safe_funcs = [
                generate_style_warnings_logs,
                generate_portability_warnings_logs,
                generate_no_flaws_logs,
                generate_resolved_vulnerability_logs,
            ]
            
            all_logs = []
            
            Logger.log("Generating synthetic vulnerable categories...")
            for func in tqdm(vulnerable_funcs, desc="Vulnerable"):
                all_logs.extend(func(Config.SAMPLES_PER_CATEGORY))
            
            Logger.log("Generating synthetic safe categories...")
            for func in tqdm(safe_funcs, desc="Safe"):
                all_logs.extend(func(Config.SAMPLES_PER_CATEGORY))
            
            # EXTRA resolved vulnerability examples
            Logger.log(f"Generating {Config.RESOLVED_VULN_SAMPLES} extra resolved examples...")
            all_logs.extend(generate_resolved_vulnerability_logs(Config.RESOLVED_VULN_SAMPLES))
            
            # ADVERSARIAL synthetic examples
            Logger.log(f"Generating {Config.ADVERSARIAL_SAMPLES} adversarial examples...")
            all_logs.extend(generate_adversarial_vulnerable_logs(Config.ADVERSARIAL_SAMPLES))
            all_logs.extend(generate_adversarial_safe_logs(Config.ADVERSARIAL_SAMPLES))
            
            # ========== NEW SEMANTIC LEARNING GENERATORS ==========
            Logger.subsection("ADDING SEMANTIC LEARNING GENERATORS")
            
            Logger.log("Generating 500 semantic buffer overflow variants...")
            all_logs.extend(generate_semantic_buffer_overflow_variants(500))
            
            Logger.log("Generating 400 semantic memory leak variants...")
            all_logs.extend(generate_semantic_memory_leak_variants(400))
            
            Logger.log("Generating 400 semantic null pointer variants...")
            all_logs.extend(generate_semantic_null_pointer_variants(400))
            
            Logger.log("Generating 400 semantic use-after-free variants...")
            all_logs.extend(generate_semantic_use_after_free_variants(400))
            
            Logger.log("Generating 300 semantic double-free variants...")
            all_logs.extend(generate_semantic_double_free_variants(300))
            
            Logger.log("Generating 300 semantic integer overflow variants...")
            all_logs.extend(generate_semantic_integer_overflow_variants(300))
            
            Logger.log("Generating 300 semantic uninitialized variable variants...")
            all_logs.extend(generate_semantic_uninitialized_variable_variants(300))
            
            Logger.log("Generating 250 semantic race condition variants...")
            all_logs.extend(generate_semantic_race_condition_variants(250))
            
            Logger.log("Generating 250 semantic format string variants...")
            all_logs.extend(generate_semantic_format_string_variants(250))
            
            Logger.log("Generating 500 concept-based vulnerabilities...")
            all_logs.extend(generate_vulnerability_by_semantic_concept(500))
            
            Logger.log("Generating 500 diverse tool outputs...")
            all_logs.extend(generate_diverse_tool_outputs(500))
            
            Logger.log("Generating 500 contrastive learning pairs (250 vuln + 250 safe)...")
            all_logs.extend(generate_contrastive_pairs(250))

            Logger.log("Generating 600 documentation safe examples (ENHANCED)...")
            all_logs.extend(generate_documentation_safe_logs(600))  # INCREASED
            
            Logger.log("Generating 500 assertion/runtime check safe examples (NEW)...")
            all_logs.extend(generate_assertion_runtime_check_safe_logs(500))  # NEW

            Logger.log("Generating 300 advisory vulnerable examples...")
            all_logs.extend(generate_advisory_vulnerable_logs(300))
            
            Logger.log("Generating 300 conceptual descriptions (expanded)...")
            all_logs.extend(generate_conceptual_vulnerability_descriptions(300))

            Logger.log("Generating 600 cross-tool semantic equivalents...")
            all_logs.extend(generate_cross_tool_semantic_equivalents(600))
            
            Logger.log("Generating 400 temporal context examples...")
            all_logs.extend(generate_temporal_context_examples(400))
            
            Logger.log("Generating 500 warning vs vulnerability examples...")
            all_logs.extend(generate_warning_vs_actual_vulnerability(500))
            
            Logger.log("Generating 500 false positive examples...")
            all_logs.extend(generate_false_positive_examples(500))
            
            Logger.log("Generating 400 severity-aware examples...")
            all_logs.extend(generate_severity_aware_examples(400))
            
            Logger.log("Generating 300 multi-language context examples...")
            all_logs.extend(generate_multi_language_context(300))
            
            Logger.log("Generating 200 compound vulnerability examples...")
            all_logs.extend(generate_compound_vulnerability_examples(200))

            Logger.log("Generating 800 compile vs runtime examples...")
            all_logs.extend(generate_compile_vs_runtime_context(800))

            Logger.log("Generating 600 exploitability context examples...")
            all_logs.extend(generate_exploitability_context(600))

            Logger.log("Generating 500 trust boundary examples...")
            all_logs.extend(generate_trust_boundary_examples(500))

            Logger.log("Generating 400 attack surface examples...")
            all_logs.extend(generate_attack_surface_context(400))

            Logger.log("Generating 600 severity classification examples...")
            all_logs.extend(generate_severity_classification(600))

            Logger.log("Generating 400 mitigation context examples...")
            all_logs.extend(generate_mitigation_context(400))
    
            # ========== END SEMANTIC GENERATORS ==========
            
            Logger.success(f"✓ Total semantic samples added: ~5,100")
            Logger.log("  Teaches semantic understanding of:")
            Logger.log("    Buffer overflows (write beyond bounds)")
            Logger.log("    Memory leaks (allocation without deallocation)")
            Logger.log("    Null pointers (access through invalid pointer)")
            Logger.log("    Use-after-free (accessing freed memory)")
            Logger.log("    Double-free (freeing already freed memory)")
            Logger.log("    Integer overflows (arithmetic exceeding bounds)")
            Logger.log("    Uninitialized variables (use before assignment)")
            Logger.log("    Race conditions (unsynchronized concurrent access)")
            Logger.log("    Format strings (user-controlled format)")
            Logger.log("")
            
            # Ultra-confusing resolved logs (KEEP YOUR EXISTING)
            Logger.log("Generating 1,000 ultra-confusing resolved examples...")
            all_logs.extend(generate_ultra_confusing_resolved_logs(1000))
            
            # Real security tool outputs (KEEP YOUR EXISTING)
            Logger.log("Generating 800 real security tool vulnerability outputs...")
            all_logs.extend(generate_actual_security_tool_vulnerabilities(800))
            
            # Ambiguous confidence breakers (KEEP YOUR EXISTING)
            Logger.log("Generating 500 ambiguous confidence-breaker examples...")
            all_logs.extend(generate_ambiguous_high_confidence_breakers(500))
            
            # Bandit-specific (KEEP YOUR EXISTING)
            Logger.log("Generating 500 bandit vulnerability examples...")
            all_logs.extend(generate_bandit_specific_vulnerabilities(500))
            
            Logger.log("Generating 300 bandit safe examples...")
            all_logs.extend(generate_bandit_safe_logs(300))
            
            synthetic_df = pd.DataFrame(all_logs)
            Logger.success(f"Generated {len(synthetic_df)} synthetic samples")
            
            # Load LLM data if available (KEEP YOUR EXISTING)
            Logger.subsection("LOADING LLM-GENERATED DATA")
            llm_df = DataGenerator.load_llm_generated_data()
            
            if not llm_df.empty:
                Logger.log("Merging synthetic and LLM datasets...")
                combined_df = pd.concat([synthetic_df, llm_df], ignore_index=True)
                Logger.success(f"Combined dataset: {len(combined_df)} total samples")
            else:
                Logger.warning("No LLM data loaded, using synthetic only")
                combined_df = synthetic_df
            
            # Shuffle and deduplicate
            combined_df = combined_df.sample(frac=1, random_state=Config.RANDOM_SEED).reset_index(drop=True)
            original_len = len(combined_df)
            combined_df = combined_df.drop_duplicates(subset=['error_log'])
            Logger.warning(f"Dropped {original_len - len(combined_df)} duplicate logs")
            
            Logger.success(f"Final base dataset: {len(combined_df)} samples")
            Logger.log(f"  Vulnerable: {(combined_df['label']==1).sum()}")
            Logger.log(f"  Safe: {(combined_df['label']==0).sum()}")
            
            # Show category breakdown
            Logger.subsection("Category Breakdown (Top 25)")
            category_counts = combined_df['category'].value_counts()
            for cat, count in category_counts.head(25).items():
                Logger.log(f"  {cat}: {count}")
            
            return combined_df
            
        except Exception as e:
            Logger.error(f"Dataset generation failed: {str(e)}")
            raise
    
    @staticmethod
    def augment_dataset(df, factor=4):
        Logger.subsection(f"AUGMENTING DATASET ({factor}x)")
        
        try:
            augmented_dfs = [df.copy()]
            
            for i in range(factor):
                df_aug = df.copy()
                df_aug['error_log'] = df_aug['error_log'].apply(
                    lambda x: re.sub(r':(\d+):', lambda m: f":{max(1, int(m.group(1)) + random.randint(-10, 10))}:", x)
                )
                augmented_dfs.append(df_aug)
            
            result_df = pd.concat(augmented_dfs, ignore_index=True)
            original_len = len(result_df)
            result_df = result_df.drop_duplicates(subset=['error_log'])
            Logger.warning(f"Dropped {original_len - len(result_df)} duplicates after augmentation")
            Logger.success(f"Final dataset: {len(result_df)} samples")
            
            return result_df
            
        except Exception as e:
            Logger.error(f"Augmentation failed: {str(e)}")
            raise
