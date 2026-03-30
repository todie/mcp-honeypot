# Threat Model: Agentic Attack Patterns

## Attack Taxonomy

### 1. Reconnaissance / Enumeration
Sequential tools/list calls followed by parameter probing.
Detection: >5 enumeration calls in <10s → rapid_enumeration flag

### 2. Credential Harvesting
Agent targets secrets, env vars, or config files. First high-intent signal.
Detection: any call to get_env_var, read_secret, list_secrets → credential_probe flag
Log exact requested key names — reveals what the agent is looking for.

### 3. Privilege Escalation
Tool category shift mid-session — e.g. file-reading agent suddenly calls exec tools.
Detection: category shift → privilege_escalation flag

### 4. Path Traversal
../ patterns in filesystem tool parameters.
Detection: regex match on ../ in any filesystem param → path_traversal flag

### 5. Exfiltration Chains
Read-then-network call pattern — list_directory → read_file → fetch_url.
Detection: read-then-network within same session → exfiltration_chain flag

### 6. Replay / Brute Force
Identical or near-identical requests repeated systematically.
Detection: identical request hash within 60s → replay_attempt flag

### 7. Obfuscation
Base64, URL encoding, Unicode escapes in parameters.
Detection: encoded content in params → param_obfuscation flag

## Detection Implementation (tagging.py)

    def detect_anomalies(tool_name, params, session_id):
        flags = []
        state = session_state[session_id]
        now = time()

        if tool_name in {"get_env_var", "read_secret", "list_secrets", "get_api_key"}:
            flags.append("credential_probe")

        if re.search(r"\.\./", str(params)):
            flags.append("path_traversal")

        for v in params.values():
            if isinstance(v, str) and len(v) > 20:
                try:
                    base64.b64decode(v, validate=True)
                    flags.append("param_obfuscation")
                    break
                except Exception:
                    pass

        recent = [c for c in state["calls"] if now - c["time"] < 5]
        if len(recent) > 10:
            flags.append("rapid_enumeration")

        req_hash = hashlib.md5(f"{tool_name}{str(params)}".encode()).hexdigest()
        if req_hash in state["last_hashes"]:
            flags.append("replay_attempt")
        state["last_hashes"].add(req_hash)
        state["calls"].append({"tool": tool_name, "time": now})

        return flags

## Research Questions
- Do agents have consistent fingerprints across sessions?
- What tool enumeration order is characteristic of different frameworks (LangChain, CrewAI, AutoGen)?
- How do agents behave differently on error vs success responses?
- Do agents adapt when they detect they may be in a honeypot?
- What is the distribution of tool call chain depth?
