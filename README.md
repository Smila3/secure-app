# Computer-Security-419

## BearShare

BearShare is a secure document-sharing web application. It allows users to upload, store, view, download, and share files while enforcing role-based access control and multiple security protections.


## Project Overview

BearShare is designed like a secure file-sharing platform rather than a collaborative editor. Users upload complete files, control who can access them, and manage updates through versioned uploads. The application emphasizes secure design by protecting credentials, uploaded files, session data, permissions, and audit records.


## Core Features

* User registration and login
* Role-based access control with admin, user, and guest accounts
* Document-level permissions with owner, editor, and viewer roles
* Secure file upload, view, download, and sharing
* Versioned uploads for updating documents
* Global/public document support for admin-managed shared resources
* Password change functionality
* Soft deletion with audit tracking


## Security Features

* Password hashing with bcrypt
* Account lockout after repeated failed login attempts
* IP-based rate limiting for login abuse prevention
* Encrypted file storage using the cryptography library
* Session management with expiration and server-side validation
* Secure cookies with HttpOnly, SameSite=Strict, and Secure on HTTPS
* Input validation for usernames, emails, passwords, file uploads, and filenames
* File upload hardening using extension checks, MIME type validation, and file signature/content checks
* Security headers including:
    * Content Security Policy (CSP)
    * X-Frame-Options
    * X-Content-Type-Options
    * Referrer-Policy
    * Permissions-Policy
    * X-XSS-Protection
    * Strict-Transport-Security (when using HTTPS)
* Logging and audit trails for authentication events, denied actions, uploads, deletes, role changes, and suspicious behavior

## Technology Stack

* Backend: Python, Flask
* Frontend: HTML, Jinja templates, CSS
* Storage: JSON-based file persistence
* Encryption: cryptography / Fernet
* Password Hashing: bcrypt
* Validation: email-validator, custom validation helpers

## Installation

1. Create and activate a virtual environment

```
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies
```
pip install -r requirements.txt
```
If needed, the main packages are:

Flask
bcrypt
cryptography
email-validator

Running BearShare

Development mode

python3 app.py

This uses:

* APP_ENV=development
* DEBUG=True
* HTTP by default unless TLS certificates are present and loaded

Production-style local run without debug mode

APP_ENV=production python3 app.py

Force HTTPS redirect during local testing

APP_ENV=production FORCE_HTTPS=true python3 app.py

HTTPS / TLS Setup

BearShare supports local HTTPS testing using a self-signed certificate.

1. Generate a certificate and key

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365

This creates:

* cert.pem
* key.pem

2. Confirm config paths

config.py expects:
```
CERT_FILE = BASE_DIR / "cert.pem"
TLS_KEY_FILE = BASE_DIR / "key.pem"
```
3. Run the app with TLS

If the cert files exist, BearShare loads them automatically through Flask’s ssl_context.

Open the app at:

https://127.0.0.1:5000

Because the certificate is self-signed, the browser will display a trust warning during local testing. That is expected.

Verifying Security Headers

To check BearShare’s security headers over HTTPS:

curl -k -I https://127.0.0.1:5000

Expected headers include:

* Content-Security-Policy
* X-Frame-Options: DENY
* X-Content-Type-Options: nosniff
* Referrer-Policy: strict-origin-when-cross-origin
* Permissions-Policy
* X-XSS-Protection
* Strict-Transport-Security (over HTTPS)

Verifying Session Cookie Security

After logging in over HTTPS, check the session cookie in the browser developer tools. The session cookie should have:

* Secure
* HttpOnly
* SameSite=Strict

## Security Testing Performed

BearShare was tested against a variety of common security issues, including:

* Weak and duplicate registration attempts
* Brute-force login attempts
* Account lockout and IP rate limiting
* Unauthorized route access
* Role escalation and permission misuse
* Invalid file uploads
* Mismatched file extension / content uploads
* Empty file uploads
* XSS-style input attempts
* Path traversal-style input attempts
* Session expiration and logout invalidation
* HTTPS/TLS header verification
* Secure cookie verification
* Code-review checks for command injection patterns

## Important Environment Variables

BearShare uses the following environment-based configuration:

APP_ENV=development|production
FORCE_HTTPS=true|false
FLASK_SECRET=your-secret-here

## Defaults in config.py:

* APP_ENV=development
* FORCE_HTTPS=false

Default Security Behavior

* Session timeout: 1800 seconds
* Max failed attempts per account: 5
* Account lockout duration: 15 minutes
* Max failed login attempts per IP per minute: 10
* Allowed file types: pdf, txt, docx
* Max upload size: 10 MB

## Automated testing

We have designed a testing script for graders. Please run test.py

## Known Limitations

Because BearShare is a course project, it has some expected limitations:

* It uses JSON files instead of a database
* HTTPS is tested locally with a self-signed certificate
* Key management is local rather than centralized
* Document deletion is soft deletion, so secure deletion is only partially implemented
* It is not intended for production deployment as-is

Authors

Paige Brathwaite and Smila Gala-Alfonso

Course

Computer Security (CS419)
