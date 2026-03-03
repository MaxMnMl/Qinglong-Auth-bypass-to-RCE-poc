# Qinglong Auth Bypass to Command Execution PoC

PoC repository for the vulnerability discussed in:
- https://github.com/whyour/qinglong/issues/2934

CVE status: **Pending assignment**

## Executive Summary
A path canonicalization / case-handling weakness in Qinglong API routing can allow an unauthenticated actor to reach a privileged command execution endpoint (`/api/system/command-run`) through case-variant paths.

If exposed over the network, this may result in **unauthenticated remote command execution**.

## Vulnerability Details
- Type: Authentication Bypass leading to Command Execution
- Probable CWE: CWE-288 (Authentication Bypass Using an Alternate Path or Channel)
- Attack Vector: Network
- Privileges Required: None (for vulnerable deployments)
- User Interaction: None

## Vulnerable Code Analysis
The bypass comes from an inconsistent case-sensitive check in auth logic, combined with case-insensitive route matching in Express.

### 1. Whitelist regex in `back/loaders/express.ts`
```ts
path: [...config.apiWhiteList, /^\/(?!api\/).*/]
```

This regex strictly checks lowercase `api`.  
Any path not starting with lowercase `/api/` can bypass the JWT check path.

### 2. Custom auth middleware uses strict lowercase prefix checks
```ts
if (!['/open/', '/api/'].some((x) => req.path.startsWith(x))) {
  return next();
}
```

The middleware also performs strict lowercase matching with `req.path.startsWith(...)`.  
So paths like `/API/...` do not match `/api/` and are directly allowed.

### 3. Express routing is case-insensitive by default
```ts
app.use(config.api.prefix, routes());
```

Even if auth checks reject only lowercase patterns, Express can still resolve `/API/...` to the same handler family as `/api/...` (default case-insensitive behavior), creating an auth bypass.

### Practical effect
An attacker can bypass token verification and call protected backend APIs directly.  
Since Qinglong exposes multiple high-impact API actions, this can be chained to command execution (for example via command-run endpoints).

### Root Cause (high level)
Security checks and route matching appear to handle URL path casing inconsistently. A request with a mixed/upper-case API prefix (for example `/aPi/system/command-run`) can be treated differently than the canonical path and may bypass expected authentication controls.

### Exploit Path
1. Attacker sends unauthenticated `PUT` request to a case-variant endpoint.
2. Backend resolves request to command execution handler.
3. Command output is returned in HTTP response.

## Impact
Successful exploitation can allow:
- Remote command execution on the Qinglong host context
- Disclosure or modification of application/runtime data
- Potential lateral movement depending on host privileges and network design

## Affected / Fixed Versions
- Affected versions: **To be confirmed by vendor/maintainers**
- Fixed version: **To be confirmed by vendor/maintainers**

Do not publish final CVE scoring until version boundaries are confirmed.

## PoC Scope
This repository is provided for:
- Security validation in authorized environments
- Reproducibility for maintainers and defenders
- Documentation for coordinated disclosure

Use only on systems you own or where you have explicit written permission.

## PoC Behavior
`poc.py` does the following:
- Detects Qinglong target (`/api/health`, `/api/system`)
- Tests known case-variant command-run paths
- Executes the command supplied by `-c` and reports response

## Reproduction
Single target:
```bash
python3 poc.py -t <host:port_or_url> -c 'echo qinglong_poc'
```

Target list:
```bash
python3 poc.py -l targets.txt -c 'echo qinglong_poc' --json -o exploited.json
```

## Mitigation Guidance
- Upgrade to the fixed Qinglong release when available.
- Normalize URL paths before authorization checks.
- Enforce strict, case-consistent route handling in middleware and reverse proxies.
- Restrict management/API exposure to trusted networks only.
- Add regression tests for case-variant endpoint access.

## Disclosure Timeline
- Initial report/discussion: https://github.com/whyour/qinglong/issues/2934
- Public PoC publication: 2026-03-03
- CVE ID publication: Pending

## Credits
- Original report/discussion: issue #2934 participants
- PoC packaging/documentation: MaxMnMl

## Legal Notice
This project is for defensive security research and authorized testing only.
The authors assume no liability for misuse.
