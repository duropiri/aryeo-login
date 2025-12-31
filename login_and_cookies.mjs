#!/usr/bin/env node
/**
 * Aryeo Headless Login & Cookie Extractor
 *
 * Automates browser login to Aryeo and extracts session cookies for replay.
 * This is browser-session replay, NOT an API integration.
 *
 * CLI Flags:
 *   --output-payload <path>       Write runner auth payload to file
 *   --runner-url <url>            Runner base URL for push
 *   --runner-token <token>        Runner auth token
 *   --push-auth                   POST auth payload to runner /auth/cookies
 *   --export-storage-state <path> Export Playwright storage state to file
 *   --help                        Show usage
 */

import { chromium } from 'playwright';
import { createHmac } from 'crypto';
import fs from 'fs';
import https from 'https';
import http from 'http';
import { URL } from 'url';

// =============================================================================
// CLI Argument Parsing
// =============================================================================

function parseArgs(argv) {
  const args = {
    outputPayload: null,
    runnerUrl: null,
    runnerToken: null,
    pushAuth: false,
    exportStorageState: null,
    help: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--output-payload':
        args.outputPayload = argv[++i];
        break;
      case '--runner-url':
        args.runnerUrl = argv[++i];
        break;
      case '--runner-token':
        args.runnerToken = argv[++i];
        break;
      case '--push-auth':
        args.pushAuth = true;
        break;
      case '--export-storage-state':
        args.exportStorageState = argv[++i];
        break;
      case '--help':
      case '-h':
        args.help = true;
        break;
    }
  }

  return args;
}

const CLI_ARGS = parseArgs(process.argv);

function showHelp() {
  console.log(`
Aryeo Login - Headless login and session extractor

Usage:
  node login_and_cookies.mjs [options]

Environment Variables:
  ARYEO_EMAIL           Aryeo account email (required)
  ARYEO_PASSWORD        Aryeo account password (required)
  ARYEO_TOTP_SECRET     TOTP secret for automatic MFA
  ARYEO_OTP             Manual OTP code
  ARYEO_SMOKE_TEST=1    Run smoke test only
  ARYEO_HEADLESS=0      Show browser window
  ARYEO_DEBUG=1         Enable debug logging

CLI Options:
  --output-payload <path>       Save runner auth payload to file
  --runner-url <url>            Runner base URL (e.g., https://runner.example.com)
  --runner-token <token>        Bearer token for runner API
  --push-auth                   POST auth payload to runner /auth/cookies
  --export-storage-state <path> Export Playwright storage state to file
  --help, -h                    Show this help

Examples:
  # Basic login (output to stdout)
  ARYEO_EMAIL="user@example.com" ARYEO_PASSWORD="pass" npm start

  # Save runner payload to file
  npm start -- --output-payload ./auth-payload.json

  # Push auth directly to runner
  npm start -- --runner-url https://runner.example.com --runner-token TOKEN --push-auth

  # Export Playwright storage state
  npm start -- --export-storage-state ./storage-state.json
`);
}

// =============================================================================
// Configuration
// =============================================================================

const CONFIG = {
  email: process.env.ARYEO_EMAIL,
  password: process.env.ARYEO_PASSWORD,
  otp: process.env.ARYEO_OTP,
  totpSecret: process.env.ARYEO_TOTP_SECRET,
  loginUrl: process.env.ARYEO_LOGIN_URL || 'https://app.aryeo.com/login',
  postLoginUrl: process.env.ARYEO_POST_LOGIN_URL || 'https://app.aryeo.com/admin/mileage',
  smokeTest: process.env.ARYEO_SMOKE_TEST === '1',
  headless: process.env.ARYEO_HEADLESS !== '0',
  timeout: parseInt(process.env.ARYEO_TIMEOUT || '30000', 10),
  selectorTimeout: parseInt(process.env.ARYEO_SELECTOR_TIMEOUT || '10000', 10),
  retryAttempts: parseInt(process.env.ARYEO_RETRY_ATTEMPTS || '3', 10),
  debug: process.env.ARYEO_DEBUG === '1',
};

// =============================================================================
// Error Classes
// =============================================================================

class LoginError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'LoginError';
    this.code = code;
  }
}

const ERROR_CODES = {
  PAGE_UNREACHABLE: 'PAGE_UNREACHABLE',
  SELECTOR_NOT_FOUND: 'SELECTOR_NOT_FOUND',
  CREDENTIAL_REJECTED: 'CREDENTIAL_REJECTED',
  VERIFICATION_REQUIRED: 'VERIFICATION_REQUIRED',
  OTP_FAILED: 'OTP_FAILED',
  COOKIES_NOT_SET: 'COOKIES_NOT_SET',
  COOKIE_DECODE_FAILED: 'COOKIE_DECODE_FAILED',
  SESSION_INVALID: 'SESSION_INVALID',
  REDIRECT_TO_LOGIN: 'REDIRECT_TO_LOGIN',
  SUBDOMAIN_ACCESS_DENIED: 'SUBDOMAIN_ACCESS_DENIED',
};

// =============================================================================
// Logging Utilities
// =============================================================================

function log(message) {
  if (CONFIG.debug) {
    console.error(`[DEBUG] ${new Date().toISOString()} ${message}`);
  }
}

function warn(message) {
  console.error(`[WARN] ${message}`);
}

function error(message, code = null) {
  const prefix = code ? `[ERROR:${code}]` : '[ERROR]';
  console.error(`${prefix} ${message}`);
}

function fatal(message, code = null) {
  error(message, code);
  process.exit(1);
}

// =============================================================================
// TOTP Implementation (RFC 6238)
// =============================================================================

function base32Decode(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanedInput = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');

  let bits = '';
  for (const char of cleanedInput) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateTOTP(secret, timeStep = 30, digits = 6) {
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / timeStep);

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const hmac = createHmac('sha1', key);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

// =============================================================================
// Selector Strategies (ordered by specificity)
// =============================================================================

const SELECTORS = {
  email: [
    'input[type="email"]',
    'input[name="email"]',
    'input[autocomplete="email"]',
    'input[autocomplete="username"]',
    'input[id*="email" i]',
    'input[placeholder*="email" i]',
    'input[aria-label*="email" i]',
  ],
  password: [
    'input[type="password"]',
    'input[name="password"]',
    'input[autocomplete="current-password"]',
    'input[id*="password" i]',
    'input[aria-label*="password" i]',
  ],
  submit: [
    'button[type="submit"]',
    'button:has-text("Sign in")',
    'button:has-text("Log in")',
    'button:has-text("Login")',
    'button:has-text("Continue")',
    'button:has-text("Submit")',
    'button:has-text("Next")',
    'input[type="submit"]',
    '[role="button"]:has-text("Sign in")',
    '[role="button"]:has-text("Log in")',
    // Case-insensitive and partial text matches
    'button:has-text("sign")',
    'button:has-text("log")',
    'button:has-text("continue")',
    // Class-based selectors (common UI frameworks)
    'button[class*="submit"]',
    'button[class*="login"]',
    'button[class*="signin"]',
    'button[class*="btn-primary"]',
    'button[class*="primary"]',
    // Broader form button selectors
    'form button:not([type="button"])',
    'form button',
    // Data attribute patterns
    'button[data-action*="submit"]',
    'button[data-action*="login"]',
    // Last resort: any button in a form-like container
    '[class*="form"] button',
    '[class*="login"] button',
    '[class*="auth"] button',
  ],
  otp: [
    'input[autocomplete="one-time-code"]',
    'input[name="code"]',
    'input[name="otp"]',
    'input[name="token"]',
    'input[name="verification_code"]',
    'input[id*="code" i]',
    'input[id*="otp" i]',
    'input[id*="verification" i]',
    'input[placeholder*="code" i]',
    'input[placeholder*="verification" i]',
    'input[inputmode="numeric"]',
    'input[type="tel"]',
  ],
};

/**
 * Wait for page to stabilize with multiple strategies
 */
async function waitForStable(page, options = {}) {
  const { timeout = CONFIG.timeout, allowTimeout = true } = options;

  // First wait for DOM content
  try {
    await page.waitForLoadState('domcontentloaded', { timeout });
  } catch (err) {
    if (!allowTimeout) throw err;
    log('domcontentloaded timeout, continuing...');
  }

  // Then wait for network to settle
  try {
    await page.waitForLoadState('networkidle', { timeout: Math.min(timeout, 10000) });
  } catch {
    log('networkidle timeout, continuing...');
  }

  // Additional short delay for SPA hydration
  await page.waitForTimeout(500);
}

/**
 * Try multiple selectors with retries, return first visible element
 */
async function findElement(page, selectorType, options = {}) {
  const selectors = SELECTORS[selectorType];
  if (!selectors) {
    throw new LoginError(
      `Unknown selector type: ${selectorType}`,
      ERROR_CODES.SELECTOR_NOT_FOUND
    );
  }

  const {
    required = true,
    timeout = CONFIG.selectorTimeout,
    retries = CONFIG.retryAttempts,
  } = options;

  const perSelectorTimeout = Math.max(500, Math.floor(timeout / selectors.length));

  for (let attempt = 1; attempt <= retries; attempt++) {
    log(`Finding ${selectorType} element (attempt ${attempt}/${retries})...`);

    for (const selector of selectors) {
      try {
        const element = page.locator(selector).first();
        await element.waitFor({
          state: 'visible',
          timeout: perSelectorTimeout,
        });

        // Verify element is actually interactive
        const isEnabled = await element.isEnabled();
        if (!isEnabled) {
          log(`Selector ${selector} found but disabled, trying next...`);
          continue;
        }

        log(`Found ${selectorType} with selector: ${selector}`);
        return element;
      } catch {
        // Continue to next selector
      }
    }

    // Wait before retry
    if (attempt < retries) {
      log(`No ${selectorType} element found, waiting before retry...`);
      await page.waitForTimeout(1000);
      await waitForStable(page, { timeout: 5000 });
    }
  }

  if (required) {
    throw new LoginError(
      `Could not find ${selectorType} element after ${retries} attempts. ` +
      `Tried selectors: ${selectors.join(', ')}`,
      ERROR_CODES.SELECTOR_NOT_FOUND
    );
  }

  return null;
}

/**
 * Check for OTP/verification page indicators
 */
async function detectVerificationPage(page) {
  const url = page.url().toLowerCase();
  const verifyPatterns = [
    '/verify', '/mfa', '/2fa', '/otp', '/challenge',
    '/confirm', '/code', '/two-factor', '/authentication'
  ];

  if (verifyPatterns.some(p => url.includes(p))) {
    log(`Verification page detected via URL: ${url}`);
    return true;
  }

  // Check for split OTP inputs (common pattern)
  const splitInputs = page.locator('input[maxlength="1"]');
  const splitCount = await splitInputs.count();
  if (splitCount >= 4 && splitCount <= 8) {
    log(`Verification page detected: ${splitCount} split OTP inputs`);
    return true;
  }

  // Check for OTP input field
  const otpElement = await findElement(page, 'otp', {
    required: false,
    timeout: 2000,
    retries: 1,
  });

  if (otpElement) {
    log('Verification page detected: OTP input found');
    return true;
  }

  return false;
}

/**
 * Check for credential rejection indicators
 */
async function detectCredentialRejection(page) {
  const errorIndicators = [
    'text=invalid credentials',
    'text=incorrect password',
    'text=wrong password',
    'text=invalid email',
    'text=user not found',
    'text=authentication failed',
    'text=login failed',
    '[class*="error"]',
    '[class*="alert-danger"]',
    '[role="alert"]',
  ];

  for (const indicator of errorIndicators) {
    try {
      const element = page.locator(indicator).first();
      const isVisible = await element.isVisible({ timeout: 500 });
      if (isVisible) {
        const text = await element.textContent();
        log(`Error indicator found: ${text}`);
        return text || 'Credential rejection detected';
      }
    } catch {
      // Continue checking
    }
  }

  return null;
}

/**
 * Fill OTP code - handles both single field and split digit fields
 */
async function fillOTP(page, code) {
  const digits = code.split('');

  // Check for split digit inputs first
  const splitInputs = page.locator('input[maxlength="1"]');
  const splitCount = await splitInputs.count();

  if (splitCount >= 4 && splitCount <= 8) {
    log(`Filling ${splitCount} split OTP input fields...`);
    for (let i = 0; i < Math.min(splitCount, digits.length); i++) {
      const input = splitInputs.nth(i);
      await input.click();
      await input.fill(digits[i]);
      await page.waitForTimeout(50); // Small delay between digits
    }
    return true;
  }

  // Single OTP input field
  const otpInput = await findElement(page, 'otp', { retries: 2 });
  if (otpInput) {
    await otpInput.click();
    await otpInput.fill(code);
    return true;
  }

  return false;
}

// =============================================================================
// Cookie Extraction
// =============================================================================

/**
 * Safely decode URI component with fallback
 */
function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch (err) {
    throw new LoginError(
      `Failed to decode XSRF token: ${err.message}. Raw value: ${value.substring(0, 50)}...`,
      ERROR_CODES.COOKIE_DECODE_FAILED
    );
  }
}

/**
 * Extract and validate cookies from browser context
 */
async function extractCookies(context) {
  const allCookies = await context.cookies();

  // Get unique domains for debugging
  const domains = [...new Set(allCookies.map(c => c.domain))];
  log(`All cookie domains: ${domains.join(', ')}`);

  // Filter for aryeo.com cookies (must work across subdomains via .aryeo.com)
  const domainCookies = allCookies.filter(c => {
    const cookieDomain = c.domain.toLowerCase();
    return cookieDomain.includes('aryeo.com');
  });

  log(`Found ${domainCookies.length} aryeo.com cookies`);

  // Find required cookies
  const xsrfCookie = domainCookies.find(c => c.name === 'XSRF-TOKEN');
  const sessionCookie = domainCookies.find(c => c.name === 'aryeo_session');

  if (!xsrfCookie) {
    throw new LoginError(
      'XSRF-TOKEN cookie not found. Authentication may have failed silently. ' +
      `Available cookies: ${domainCookies.map(c => c.name).join(', ') || 'none'}`,
      ERROR_CODES.COOKIES_NOT_SET
    );
  }

  if (!sessionCookie) {
    throw new LoginError(
      'aryeo_session cookie not found. Session was not established. ' +
      `Available cookies: ${domainCookies.map(c => c.name).join(', ') || 'none'}`,
      ERROR_CODES.COOKIES_NOT_SET
    );
  }

  // Log cookie domains for debugging subdomain scope
  log(`XSRF-TOKEN domain: ${xsrfCookie.domain}, aryeo_session domain: ${sessionCookie.domain}`);

  // Cookie header uses raw (URL-encoded) values
  const cookieHeader = `XSRF-TOKEN=${xsrfCookie.value}; aryeo_session=${sessionCookie.value}`;

  // x-xsrf-token header uses URL-decoded value (with guard)
  const xsrfHeader = safeDecodeURIComponent(xsrfCookie.value);

  // Get expiration (sessions can be invalidated anytime regardless of cookie expiry)
  const expiresAt = sessionCookie.expires > 0
    ? new Date(sessionCookie.expires * 1000).toISOString()
    : null;

  return {
    cookieHeader,
    xsrfHeader,
    expiresAt,
    debugDomains: domains,
    // Include raw cookies for storage state export (not in stdout output)
    _rawCookies: domainCookies,
  };
}

// =============================================================================
// Login Flow
// =============================================================================

/**
 * Navigate to login page with retry logic
 */
async function navigateToLogin(page) {
  log(`Navigating to login URL: ${CONFIG.loginUrl}`);

  for (let attempt = 1; attempt <= CONFIG.retryAttempts; attempt++) {
    try {
      const response = await page.goto(CONFIG.loginUrl, {
        waitUntil: 'domcontentloaded',
        timeout: CONFIG.timeout,
      });

      if (!response) {
        throw new Error('No response received');
      }

      const status = response.status();
      if (status >= 400) {
        throw new Error(`HTTP ${status}`);
      }

      await waitForStable(page);

      // Verify we're on the login page
      const currentUrl = page.url();
      log(`Landed on: ${currentUrl}`);

      return;
    } catch (err) {
      warn(`Navigation attempt ${attempt} failed: ${err.message}`);
      if (attempt === CONFIG.retryAttempts) {
        throw new LoginError(
          `Login page unreachable after ${CONFIG.retryAttempts} attempts: ${err.message}. ` +
          `URL: ${CONFIG.loginUrl}`,
          ERROR_CODES.PAGE_UNREACHABLE
        );
      }
      await page.waitForTimeout(2000);
    }
  }
}

/**
 * Verify login by navigating to target subdomain
 * Must be called BEFORE cookie extraction to ensure cookies work cross-subdomain
 */
async function verifyLoginWithSubdomain(page) {
  log(`Verifying login by navigating to: ${CONFIG.postLoginUrl}`);

  try {
    // Inertia/SPAs can hang on domcontentloaded/networkidle.
    // "commit" means navigation happened and we got a response.
    const response = await page.goto(CONFIG.postLoginUrl, {
      waitUntil: 'commit',
      timeout: CONFIG.timeout,
    });

    // Give the SPA a moment to hydrate/redirect if it's going to.
    await page.waitForTimeout(1500);

    const status = response?.status() || 0;
    const finalUrl = page.url();

    log(`Post-login navigation: ${finalUrl} (HTTP ${status})`);

    // Only check for redirect back to login AFTER hydration settle
    if (finalUrl.includes('/login')) {
      throw new LoginError(
        `Redirected to login page after authentication. ` +
          `Target: ${CONFIG.postLoginUrl}, Landed: ${finalUrl}`,
        ERROR_CODES.REDIRECT_TO_LOGIN
      );
    }

    // Check for auth failure status codes
    if (status === 401 || status === 403) {
      throw new LoginError(
        `Access denied to target URL (HTTP ${status}). Cookies may not have correct domain scope.`,
        ERROR_CODES.SUBDOMAIN_ACCESS_DENIED
      );
    }

    // Check for 419 (Laravel CSRF mismatch)
    if (status === 419) {
      throw new LoginError(
        'CSRF token mismatch (HTTP 419). Session may be invalid.',
        ERROR_CODES.SESSION_INVALID
      );
    }

    // Optional light content check (do not block on full content load)
    // Some SPAs can still render minimal HTML; this is just a sanity check.
    let content = '';
    try {
      content = await page.content();
    } catch {
      // ignore
    }

    const lowerContent = (content || '').toLowerCase();
    if (
      lowerContent.includes('unauthorized') ||
      lowerContent.includes('access denied') ||
      lowerContent.includes('please log in')
    ) {
      throw new LoginError(
        'Page content indicates authentication failure.',
        ERROR_CODES.SESSION_INVALID
      );
    }

    log('Login verification successful');
    return true;
  } catch (err) {
    if (err instanceof LoginError) throw err;
    throw new LoginError(
      `Failed to verify login: ${err.message}`,
      ERROR_CODES.SESSION_INVALID
    );
  }
}

/**
 * Perform the complete login flow
 */
async function performLogin(page, context) {
  // Step 1: Navigate to login page
  await navigateToLogin(page);

  // Step 2: Enter email
  log('Step: Enter email');
  const emailInput = await findElement(page, 'email');
  await emailInput.click();
  await emailInput.fill(CONFIG.email);

  // Check if password is visible (combined form) or email-first flow
  const passwordVisible = await findElement(page, 'password', {
    required: false,
    timeout: 3000,
    retries: 1,
  });

  if (!passwordVisible) {
    // Email-first flow: submit email and wait for next step
    log('Email-first flow detected, submitting email...');
    const submitBtn = await findElement(page, 'submit');
    await submitBtn.click();
    await waitForStable(page);

    // Check for errors after email submission
    const emailError = await detectCredentialRejection(page);
    if (emailError) {
      throw new LoginError(
        `Email rejected: ${emailError}`,
        ERROR_CODES.CREDENTIAL_REJECTED
      );
    }
  }

  // Step 3: Enter password
  log('Step: Enter password');
  const passwordInput = await findElement(page, 'password');
  await passwordInput.click();
  await passwordInput.fill(CONFIG.password);

  // Step 4: Submit login form
  log('Step: Submit login form');
  const submitBtn = await findElement(page, 'submit');
  await submitBtn.click();
  await waitForStable(page);

  // Check for credential rejection
  const credentialError = await detectCredentialRejection(page);
  if (credentialError) {
    throw new LoginError(
      `Credentials rejected: ${credentialError}`,
      ERROR_CODES.CREDENTIAL_REJECTED
    );
  }

  // Step 5: Handle verification/OTP if required
  if (await detectVerificationPage(page)) {
    log('Step: Handle verification/OTP');

    let otpCode = CONFIG.otp;

    if (!otpCode && CONFIG.totpSecret) {
      log('Generating TOTP from secret...');
      otpCode = generateTOTP(CONFIG.totpSecret);
      log(`Generated TOTP: ${otpCode.substring(0, 2)}****`);
    }

    if (!otpCode) {
      throw new LoginError(
        'Verification required but no OTP provided. ' +
        'Set ARYEO_OTP for manual code or ARYEO_TOTP_SECRET for automatic generation. ' +
        'Note: Email/SMS magic links require separate automation.',
        ERROR_CODES.VERIFICATION_REQUIRED
      );
    }

    const filled = await fillOTP(page, otpCode);
    if (!filled) {
      throw new LoginError(
        'Could not find OTP input field on verification page.',
        ERROR_CODES.SELECTOR_NOT_FOUND
      );
    }

    // Submit OTP (may auto-submit on last digit)
    await page.waitForTimeout(500);
    const otpSubmit = await findElement(page, 'submit', {
      required: false,
      timeout: 2000,
      retries: 1,
    });
    if (otpSubmit) {
      await otpSubmit.click();
    }
    await waitForStable(page);

    // Check if OTP failed
    if (await detectVerificationPage(page)) {
      const otpError = await detectCredentialRejection(page);
      throw new LoginError(
        `OTP verification failed${otpError ? `: ${otpError}` : ''}. ` +
        'Check your TOTP secret or provide a valid manual code.',
        ERROR_CODES.OTP_FAILED
      );
    }
  }

  // Step 6: Navigate to target subdomain BEFORE extracting cookies
  // This ensures cookies are valid across subdomains
  await verifyLoginWithSubdomain(page);

  // Step 7: Extract and validate cookies
  log('Step: Extract cookies');
  return await extractCookies(context);
}

/**
 * Run smoke test (connectivity check without login)
 */
async function runSmokeTest(page, context) {
  log('Running smoke test...');

  try {
    await navigateToLogin(page);
  } catch (err) {
    return {
      smokeTest: true,
      success: false,
      error: err.message,
      errorCode: err.code || 'UNKNOWN',
    };
  }

  const cookies = await context.cookies();
  const domains = [...new Set(cookies.map(c => c.domain))];
  const aryeoCookies = cookies.filter(c => c.domain.includes('aryeo.com'));

  return {
    smokeTest: true,
    success: true,
    url: page.url(),
    cookieCount: cookies.length,
    aryeoCookieCount: aryeoCookies.length,
    domains,
    hasXSRF: aryeoCookies.some(c => c.name === 'XSRF-TOKEN'),
    hasSession: aryeoCookies.some(c => c.name === 'aryeo_session'),
  };
}

// =============================================================================
// Runner Auth Payload & Push
// =============================================================================

/**
 * Create runner auth payload suitable for POST /auth/cookies
 */
function createRunnerAuthPayload(result) {
  return {
    cookieHeader: result.cookieHeader,
    xsrfHeader: result.xsrfHeader,
    expiresAt: result.expiresAt,
  };
}

/**
 * Push auth payload to runner /auth/cookies endpoint
 */
async function pushAuthToRunner(payload, runnerUrl, runnerToken) {
  return new Promise((resolve, reject) => {
    const url = new URL('/auth/cookies', runnerUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const postData = JSON.stringify(payload);

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'Authorization': `Bearer ${runnerToken}`,
      },
    };

    log(`Pushing auth to: ${url.toString()}`);

    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, body: response });
          } else {
            reject(new Error(`Runner returned ${res.statusCode}: ${JSON.stringify(response)}`));
          }
        } catch (e) {
          reject(new Error(`Failed to parse runner response: ${data}`));
        }
      });
    });

    req.on('error', (e) => {
      reject(new Error(`Failed to connect to runner: ${e.message}`));
    });

    req.write(postData);
    req.end();
  });
}

// =============================================================================
// Playwright Storage State Export
// =============================================================================

/**
 * Convert browser cookies to Playwright storage state format
 */
function createPlaywrightStorageState(cookies) {
  // Convert to Playwright cookie format
  const playwrightCookies = cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    expires: c.expires,
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: c.sameSite,
  }));

  return {
    cookies: playwrightCookies,
    origins: [],
  };
}

/**
 * Export Playwright storage state to file
 */
function exportStorageState(storageState, filePath) {
  const content = JSON.stringify(storageState, null, 2);
  fs.writeFileSync(filePath, content, { mode: 0o600 });
  log(`Exported Playwright storage state to: ${filePath}`);
  return {
    path: filePath,
    cookieCount: storageState.cookies.length,
    cookieNames: [...new Set(storageState.cookies.map(c => c.name))],
  };
}

// =============================================================================
// Main Entry Point
// =============================================================================

async function main() {
  // Show help if requested
  if (CLI_ARGS.help) {
    showHelp();
    process.exit(0);
  }

  // Validate CLI args for push
  if (CLI_ARGS.pushAuth) {
    if (!CLI_ARGS.runnerUrl) {
      fatal('--runner-url is required when using --push-auth', 'CONFIG_ERROR');
    }
    if (!CLI_ARGS.runnerToken) {
      fatal('--runner-token is required when using --push-auth', 'CONFIG_ERROR');
    }
  }

  // Validate configuration
  if (!CONFIG.smokeTest) {
    if (!CONFIG.email) {
      fatal('ARYEO_EMAIL environment variable is required', 'CONFIG_ERROR');
    }
    if (!CONFIG.password) {
      fatal('ARYEO_PASSWORD environment variable is required', 'CONFIG_ERROR');
    }
  }

  let browser = null;

  try {
    log('Launching browser...');
    browser = await chromium.launch({
      headless: CONFIG.headless,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--disable-dev-shm-usage',
        '--no-sandbox',
      ],
    });

    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 720 },
      locale: 'en-US',
      timezoneId: 'America/New_York',
    });

    const page = await context.newPage();
    page.setDefaultTimeout(CONFIG.timeout);

    let result;

    if (CONFIG.smokeTest) {
      result = await runSmokeTest(page, context);
    } else {
      result = await performLogin(page, context);
    }

    // Extract raw cookies before cleaning result for output
    const rawCookies = result._rawCookies;
    delete result._rawCookies;

    // Handle --output-payload: save runner auth payload to file
    if (CLI_ARGS.outputPayload && !CONFIG.smokeTest) {
      const payload = createRunnerAuthPayload(result);
      fs.writeFileSync(CLI_ARGS.outputPayload, JSON.stringify(payload, null, 2), { mode: 0o600 });
      log(`Runner auth payload saved to: ${CLI_ARGS.outputPayload}`);
      console.error(`[INFO] Saved runner auth payload to: ${CLI_ARGS.outputPayload}`);
    }

    // Handle --push-auth: POST to runner /auth/cookies
    if (CLI_ARGS.pushAuth && !CONFIG.smokeTest) {
      const payload = createRunnerAuthPayload(result);
      try {
        const pushResult = await pushAuthToRunner(payload, CLI_ARGS.runnerUrl, CLI_ARGS.runnerToken);
        console.error(`[INFO] Runner push successful: ${pushResult.body.cookieCount} cookies, names: ${pushResult.body.cookieNames?.join(', ') || 'N/A'}`);
      } catch (pushErr) {
        error(`Runner push failed: ${pushErr.message}`, 'RUNNER_PUSH_FAILED');
        // Don't exit - still output the result
      }
    }

    // Handle --export-storage-state: export Playwright storage state
    if (CLI_ARGS.exportStorageState && !CONFIG.smokeTest && rawCookies) {
      const storageState = createPlaywrightStorageState(rawCookies);
      const exportResult = exportStorageState(storageState, CLI_ARGS.exportStorageState);
      console.error(`[INFO] Exported storage state: ${exportResult.cookieCount} cookies to ${exportResult.path}`);
    }

    // Add playwrightStorageState to output if we have raw cookies (for backward compat with README examples)
    if (rawCookies && !CONFIG.smokeTest) {
      result.playwrightStorageState = createPlaywrightStorageState(rawCookies);
    }

    // Output result as JSON to stdout
    console.log(JSON.stringify(result, null, 2));

    await browser.close();
    process.exit(0);

  } catch (err) {
    const code = err.code || 'UNKNOWN_ERROR';
    error(err.message, code);

    if (CONFIG.debug && err.stack) {
      console.error('\nStack trace:');
      console.error(err.stack);
    }

    // Provide actionable guidance based on error type
    switch (code) {
      case ERROR_CODES.PAGE_UNREACHABLE:
        console.error('\nAction: Check network connectivity and verify the login URL is correct.');
        break;
      case ERROR_CODES.CREDENTIAL_REJECTED:
        console.error('\nAction: Verify ARYEO_EMAIL and ARYEO_PASSWORD are correct.');
        break;
      case ERROR_CODES.VERIFICATION_REQUIRED:
        console.error('\nAction: Provide ARYEO_OTP or ARYEO_TOTP_SECRET for MFA.');
        break;
      case ERROR_CODES.OTP_FAILED:
        console.error('\nAction: Check TOTP secret or provide a fresh manual OTP code.');
        break;
      case ERROR_CODES.COOKIES_NOT_SET:
        console.error('\nAction: Run smoke test (ARYEO_SMOKE_TEST=1) to diagnose cookie issues.');
        break;
      case ERROR_CODES.COOKIE_DECODE_FAILED:
        console.error('\nAction: XSRF token has invalid encoding. This may indicate a server issue.');
        break;
      case ERROR_CODES.REDIRECT_TO_LOGIN:
        console.error('\nAction: Login succeeded but session is not valid. Cookies may not work across subdomains.');
        break;
      case ERROR_CODES.SESSION_INVALID:
        console.error('\nAction: Session may have expired or cookies are not cross-subdomain. Retry login.');
        break;
    }

    if (browser) {
      try {
        await browser.close();
      } catch {
        // Ignore close errors
      }
    }

    process.exit(1);
  }
}

main();
