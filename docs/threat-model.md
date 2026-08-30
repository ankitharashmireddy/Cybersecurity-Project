# Threat Model - Password Strength Checker

## Assets

- **Password input**: The password string entered by the user in the form
- **Analysis results**: Strength score, entropy, recommendations displayed to the user
- **Flask session**: SECRET_KEY configuration (used for CSRF protection on form submissions)
- **Source code**: The Python/HTML/CSS/JS implementation

## Trust Boundaries

1. **User Browser → Flask Application**: HTTPS-protected HTTP communication
   - The password is sent from the browser to the Flask backend via POST
   - No authentication/authorization; any user can access the analyzer
   - The Flask backend processes the password using the local analyzer engine

2. **Flask Application → Local Filesystem**: Read-only access to `common_passwords.txt`
   - No database writes; no file writes of user passwords
   - Analysis results are generated in-memory only

3. **Client-Side JavaScript → Server**: POST communication
   - JavaScript sends password to `/analyze` endpoint
   - Results are returned and displayed in the UI

## Attack Surfaces

| Surface | Description |
|---------|-------------|
| **Password submission field** | User-entered value; could contain unexpected input, XSS vectors, or extremely long strings |
| **Flask backend analysis** | Python code execution with user-controlled password; potential for unhandled exceptions with malicious input |
| **HTTP response rendering** | If password were accidentally included in templates, could appear in rendered HTML |
| **JavaScript DOM manipulation** | If unsafe innerHTML were used with password data, could lead to XSS |
| **Error pages** | If error responses included internal details or the password itself |
| **Network traffic** | Unprotected HTTP would expose password; HTTPS mitigates this |
| **Browser storage** | If JavaScript were to mistakenly write password to localStorage or sessionStorage |

## Threats & Mitigations

| Threat | Attack Surface | Impact | Likelihood | Mitigation | Status |
|--------|---------------|--------|------------|------------|--------|
| **Password exposure in transit** | Network interception (unprotected HTTP) | High | Low | HTTPS enforcement; application only works over HTTPS in production | Mitigated |
| **Password displayed in results** | UI rendering; template injection | High | Low | Jinja2 auto-escaping; password never sent to results; privacy notice in UI | Mitigated |
| **Password logged server-side** | Flask logging misconfiguration | Medium | Low | Code review confirmed no password logging; `app.logger.error()` uses parameterized format | Mitigated |
| **Password stored persistently** | Database, file storage | High | Low | No persistent storage; passwords are in-memory only; cleared after analysis | Mitigated |
| **XSS via password display** | Unsafe HTML injection with user data | High | Low | Jinja2 auto-escaping; JavaScript uses `textContent`/`createElement`; password never displayed | Mitigated |
| **CSRF on form submission** | Form POST without validation | Medium | Low | Application has no authentication/state-changing actions; CSRF is low risk; Flask SECRET_KEY configured as development fallback | Mitigated/Not Applicable |
| **Information disclosure via errors** | Error responses including internal details | Medium | Low | Error handlers return generic messages; no stack traces or password in client responses | Mitigated |
| **Common password dataset limitations** | Small local list cannot represent all compromised passwords | Low | High | Dataset documented as educational-only; cannot claim breach-checking capability | Accepted limitation |
| **Entropy overstatement** | Theoretical entropy presented without adequate disclaimer | Medium | Medium | Documentation includes entropy explanation; entropy labeled "Estimated Theoretical Entropy" | Mitigated |

## Mitigation Summary

- **Privacy-first design**: Password never leaves the browser→Flask pathway in a storable/loggable form
- **Jinja2 auto-escaping**: Prevents XSS in template rendering
- **Safe DOM APIs**: JavaScript uses `textContent` and `createElement`, not `innerHTML`
- **No persistent storage**: Passwords are processed and discarded; no database, no file logging
- **Error handling**: Generic error messages to clients; detailed logging only on server side
- **HTTPS recommended**: Application should be served over HTTPS in production
- **Development-only SECRET_KEY**: Clearly documented as development fallback

## Data Flow Diagram

```
User Browser
  |
  |-- Clicks "Analyze Password"
  |
  v
POST /analyze
  |  password=<user_password>
  |
  v
Flask Backend
  |  _analyze_password_safe(password)
  |  ↓
  |  Results dict (NO password key)
  |  ↓
JSON response / HTML template render
  |  ↓
Password NEVER included in output
  |
  v
User sees strength score, entropy, recommendations
  |
  v
Password cleared from in-memory state
```

## Privacy Considerations

- **Password not stored**: After analysis, password is not saved to disk, database, or session
- **Password not logged**: Flask logger does not include the password; parameterized error messages
- **Password not sent externally**: No third-party APIs; no network transmission except Flask internal POST
- **Password not in DOM after analysis**: Results section shows derived metrics, not the password itself
- **Clear privacy notice**: UI includes explicit privacy notice explaining these points