# Aryeo Headless Login & Cookie Extractor

Headless browser login and cookie extractor for Aryeo using Playwright.

**This is browser-session replay, not an API integration.** Aryeo does not expose a public API for this functionality. This tool automates browser login and extracts session cookies for replay. Sessions can be invalidated by Aryeo at any time (logout, security events, server restarts, idle timeout). Plan for re-authentication on every workflow run.

## Installation

```bash
cd aryeo-login
npm install
```

Installs Playwright and downloads Chromium.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ARYEO_EMAIL` | Yes* | Aryeo account email |
| `ARYEO_PASSWORD` | Yes* | Aryeo account password |
| `ARYEO_OTP` | No | Manual OTP code (TOTP-based MFA only) |
| `ARYEO_TOTP_SECRET` | No | Base32 TOTP secret for automatic code generation (RFC 6238) |
| `ARYEO_LOGIN_URL` | No | Login URL (default: `https://app.aryeo.com/login`) |
| `ARYEO_POST_LOGIN_URL` | No | URL to verify login (default: `https://virtual-xposure.aryeo.com/admin/mileage`) |
| `ARYEO_SMOKE_TEST` | No | Set to `1` for smoke test mode |
| `ARYEO_HEADLESS` | No | Set to `0` to show browser (debugging) |
| `ARYEO_TIMEOUT` | No | Timeout in ms (default: `30000`) |
| `ARYEO_DEBUG` | No | Set to `1` for debug logging to stderr |

*Not required for smoke test mode

### MFA Support

- **TOTP-based MFA**: Supported via `ARYEO_TOTP_SECRET` (automatic) or `ARYEO_OTP` (manual). Only works if your Aryeo account uses TOTP (authenticator app).
- **Email/SMS magic links**: Not supported. These require intercepting email/SMS which needs separate automation.

## Usage

### Basic Login

```bash
export ARYEO_EMAIL="your@email.com"
export ARYEO_PASSWORD="your-password"
npm start
```

### With TOTP (Automatic OTP)

For accounts with TOTP-based MFA (authenticator app):

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
  "debugDomains": [".aryeo.com", "app.aryeo.com"]
}
```

| Field | Description |
|-------|-------------|
| `cookieHeader` | Value for `cookie` header. Cookies scoped to `.aryeo.com` (works across subdomains). |
| `xsrfHeader` | URL-decoded XSRF token for `x-xsrf-token` header. |
| `expiresAt` | Cookie expiration (ISO 8601) or `null`. **Do not rely on this; sessions can be invalidated at any time.** |
| `debugDomains` | All cookie domains observed. |

## n8n Integration

### Execute Command Node

Command:
```
node /path/to/aryeo-login/login_and_cookies.mjs
```

Set environment variables in the node or globally in n8n.

### Parse Output (Code Node)

The Execute Command output structure varies by n8n version. Use defensive parsing:

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

Required headers for authenticated requests:

| Header | Value |
|--------|-------|
| `cookie` | `{{ $json.cookieHeader }}` |
| `x-xsrf-token` | `{{ $json.xsrfHeader }}` |
| `X-Inertia` | `true` |
| `Accept` | `application/json` |
| `X-Requested-With` | `XMLHttpRequest` |

## Health Check & Auto-Refresh

Sessions are not reliable. Detect failures and re-authenticate.

### Failure Indicators

- HTTP 302 redirect to `/login`
- HTTP 401 Unauthorized
- HTTP 419 Session Expired (Laravel CSRF mismatch)

### n8n Auto-Refresh Pattern

After HTTP Request node, add an IF node to detect auth failure:

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

On failure:
1. Re-run login script (Execute Command)
2. Parse new cookies (Code node)
3. Retry request with new cookies (HTTP Request)
4. Limit to 1 retry to avoid loops

```
HTTP Request → IF (auth failure?)
  ├─ No  → Continue
  └─ Yes → Login → Parse → Retry → Continue
```

## Getting Your TOTP Secret

1. Go to Aryeo account security settings
2. Enable two-factor authentication (must be TOTP/authenticator app, not email/SMS)
3. When shown the QR code, select "Manual entry" or "Can't scan?"
4. Copy the base32 secret (e.g., `JBSWY3DPEHPK3PXP`)
5. Set `ARYEO_TOTP_SECRET`

## Troubleshooting

### "XSRF-TOKEN cookie not found"

- Run smoke test: `npm run smoke`
- Check if bot protection is blocking headless access

### "Redirected back to login page"

- Credentials may be wrong
- MFA may be required
- Session may have been invalidated server-side
- Run debug mode: `ARYEO_HEADLESS=0 ARYEO_DEBUG=1 npm start`

### "OTP verification failed"

- Verify TOTP secret is correct base32
- Check system clock synchronization (TOTP is time-sensitive)
- If using email/SMS MFA, this tool cannot handle it

### Timeout errors

- Increase timeout: `ARYEO_TIMEOUT=60000 npm start`
- Check network connectivity

### Browser not found

```bash
npx playwright install chromium
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (JSON output on stdout) |
| 1 | Failure (error message on stderr) |

## Security

- Do not commit credentials
- Use environment variables or secrets manager
- Do not cache sessions; re-authenticate as needed
- Rotate credentials periodically
