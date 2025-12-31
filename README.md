# Aryeo Login

Headless browser login and session extractor for Aryeo using Playwright.

## Overview

This tool automates Aryeo login and extracts session data in two formats:
- **Cookie headers** for direct HTTP requests
- **Playwright storage state** for browser automation (compatible with [aryeo-delivery-runner](https://github.com/duropiri/aryeo-runner))

> **Note:** This is browser-session replay, not an API integration. Aryeo does not expose a public API for authentication. Sessions can be invalidated at any time (logout, security events, idle timeout). Plan for re-authentication.

## Quick Start

```bash
# Install
npm install

# Login and extract session
ARYEO_EMAIL="your@email.com" ARYEO_PASSWORD="your-password" npm start
```

## Installation

```bash
git clone https://github.com/duropiri/aryeo-login.git
cd aryeo-login
npm install
```

This installs Playwright and downloads Chromium automatically.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ARYEO_EMAIL` | Yes* | Aryeo account email |
| `ARYEO_PASSWORD` | Yes* | Aryeo account password |
| `ARYEO_OTP` | No | Manual OTP code (TOTP-based MFA only) |
| `ARYEO_TOTP_SECRET` | No | Base32 TOTP secret for automatic code generation |
| `ARYEO_LOGIN_URL` | No | Login URL (default: `https://app.aryeo.com/login`) |
| `ARYEO_POST_LOGIN_URL` | No | URL to verify login (default: `https://virtual-xposure.aryeo.com/admin/mileage`) |
| `ARYEO_SMOKE_TEST` | No | Set to `1` for smoke test mode |
| `ARYEO_HEADLESS` | No | Set to `0` to show browser (debugging) |
| `ARYEO_TIMEOUT` | No | Timeout in ms (default: `30000`) |
| `ARYEO_DEBUG` | No | Set to `1` for debug logging |

*Not required for smoke test mode

## Usage

### Basic Login

```bash
export ARYEO_EMAIL="your@email.com"
export ARYEO_PASSWORD="your-password"
npm start
```

### With TOTP (Automatic MFA)

```bash
export ARYEO_EMAIL="your@email.com"
export ARYEO_PASSWORD="your-password"
export ARYEO_TOTP_SECRET="YOUR_BASE32_SECRET"
npm start
```

### Smoke Test

Test connectivity without credentials:

```bash
npm run smoke
```

### Debug Mode

```bash
ARYEO_DEBUG=1 ARYEO_HEADLESS=0 npm start
```

## Output Format

JSON to stdout on success:

```json
{
  "cookieHeader": "XSRF-TOKEN=eyJp...%3D; aryeo_session=eyJp...",
  "xsrfHeader": "eyJp...=",
  "expiresAt": "2025-01-15T12:00:00.000Z",
  "debugDomains": [".aryeo.com", "app.aryeo.com"],
  "playwrightStorageState": {
    "cookies": [
      {
        "name": "XSRF-TOKEN",
        "value": "eyJp...",
        "domain": ".aryeo.com",
        "path": "/",
        "expires": 1736942400,
        "httpOnly": false,
        "secure": true,
        "sameSite": "Lax"
      }
    ],
    "origins": []
  }
}
```

| Field | Description |
|-------|-------------|
| `cookieHeader` | Value for `Cookie` HTTP header |
| `xsrfHeader` | URL-decoded XSRF token for `X-XSRF-TOKEN` header |
| `expiresAt` | Soonest cookie expiration (ISO 8601) or `null` |
| `debugDomains` | All cookie domains observed |
| `playwrightStorageState` | Playwright-compatible storage state for browser automation |

## Integration with aryeo-delivery-runner

The `playwrightStorageState` output can be pushed directly to the [aryeo-delivery-runner](https://github.com/duropiri/aryeo-runner) API:

### Extract and Save Locally

```bash
# Run login and save storage state
ARYEO_EMAIL="your@email.com" ARYEO_PASSWORD="your-password" npm start \
  | jq '.playwrightStorageState' > aryeo-storage-state.json
```

### Push to Runner API

```bash
# Extract storage state and push to runner
ARYEO_EMAIL="your@email.com" ARYEO_PASSWORD="your-password" npm start \
  | jq '.playwrightStorageState' \
  | curl -X POST https://runner.yourdomain.com/auth/storage-state \
      -H "Authorization: Bearer YOUR_RUNNER_TOKEN" \
      -H "Content-Type: application/json" \
      -d @-
```

### SCP to Server

```bash
# Save locally then copy to server
ARYEO_EMAIL="your@email.com" ARYEO_PASSWORD="your-password" npm start \
  | jq '.playwrightStorageState' > aryeo-storage-state.json

scp aryeo-storage-state.json user@server:/opt/aryeo-runner/data/auth/
```

## n8n Integration

### Execute Command Node

```
node /path/to/aryeo-login/login_and_cookies.mjs
```

Set environment variables in the node or globally in n8n.

### Parse Output (Code Node)

```javascript
const item = $input.first().json;

// Handle different Execute Command output structures
const rawOutput = item.stdout ?? item.data ?? item.output ?? '';

if (!rawOutput || typeof rawOutput !== 'string') {
  throw new Error('No stdout from login script');
}

let result;
try {
  result = JSON.parse(rawOutput.trim());
} catch (e) {
  throw new Error(`Failed to parse login output: ${rawOutput.substring(0, 200)}`);
}

if (!result.cookieHeader || !result.xsrfHeader) {
  throw new Error('Login script returned incomplete data');
}

return [{ json: result }];
```

### HTTP Request Headers

| Header | Value |
|--------|-------|
| `Cookie` | `{{ $json.cookieHeader }}` |
| `X-XSRF-TOKEN` | `{{ $json.xsrfHeader }}` |
| `X-Inertia` | `true` |
| `Accept` | `application/json` |
| `X-Requested-With` | `XMLHttpRequest` |

## MFA Support

| Type | Supported | Notes |
|------|-----------|-------|
| TOTP (Authenticator App) | Yes | Via `ARYEO_TOTP_SECRET` or `ARYEO_OTP` |
| Email Magic Link | No | Requires email interception |
| SMS Code | No | Requires SMS interception |

### Getting Your TOTP Secret

1. Go to Aryeo account security settings
2. Enable two-factor authentication (select authenticator app)
3. Click "Manual entry" or "Can't scan?"
4. Copy the base32 secret (e.g., `JBSWY3DPEHPK3PXP`)
5. Set `ARYEO_TOTP_SECRET`

## Auto-Refresh Pattern

Sessions are not reliable. Detect failures and re-authenticate.

### Failure Indicators

- HTTP 302 redirect to `/login`
- HTTP 401 Unauthorized
- HTTP 419 Session Expired (Laravel CSRF mismatch)

### n8n Auto-Refresh

```javascript
const statusCode = $input.first().json.statusCode ?? 200;
const headers = $input.first().json.headers ?? {};
const location = headers.location ?? '';

const isAuthFailure =
  statusCode === 401 ||
  statusCode === 419 ||
  (statusCode === 302 && location.includes('/login'));

return isAuthFailure;
```

Flow:
```
HTTP Request → IF (auth failure?)
  ├─ No  → Continue
  └─ Yes → Login → Parse → Retry → Continue
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "XSRF-TOKEN cookie not found" | Run smoke test: `npm run smoke` |
| "Redirected back to login" | Check credentials, MFA, or run debug mode |
| "OTP verification failed" | Verify TOTP secret, check system clock |
| Timeout errors | Increase: `ARYEO_TIMEOUT=60000 npm start` |
| Browser not found | Run: `npx playwright install chromium` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (JSON on stdout) |
| 1 | Failure (error on stderr) |

## Security

- Never commit credentials
- Use environment variables or a secrets manager
- Re-authenticate as needed (don't cache sessions indefinitely)
- Rotate credentials periodically

## License

MIT
