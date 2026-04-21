# this file stores the main configuration values used throughout the application.
# instead of hardcoding paths and security settings in many different files,
# the app imports them from here.
#
# this makes the project easier to manage because:
# - file locations are defined in one place
# - security-related limits are easy to adjust
# - environment-based settings such as debug mode and forced https
#   can be controlled without rewriting the application code

import os
from pathlib import Path

# base_dir is the folder where config.py itself lives.
# many other project paths are built relative to this location.
BASE_DIR = Path(__file__).resolve().parent

# define the main project folders.
# these are used throughout the application for storing templates, data, logs, and files.
DOCS_DIR = BASE_DIR / "docs"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
ENCRYPTED_DIR = BASE_DIR / "encrypted_files"

# define the main json data files used by the application.
# because this project uses file-based storage instead of a database,
# these files hold the application's persistent state.
USERS_FILE = DATA_DIR / "users.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
DOCUMENTS_FILE = DATA_DIR / "documents.json"
SHARES_FILE = DATA_DIR / "shares.json"
AUDIT_FILE = DATA_DIR / "audit.json"
FAILED_LOGINS_FILE = DATA_DIR / "failed_logins.json"

# define the log file locations.
# security logs record suspicious or security-relevant events.
# access logs record normal user actions and successful access activity.
SECURITY_LOG_FILE = LOG_DIR / "security.log"
ACCESS_LOG_FILE = LOG_DIR / "access.log"

# define the file where the symmetric encryption key is stored.
# this key is used to encrypt and decrypt uploaded document contents.
SECRET_KEY_FILE = BASE_DIR / "secret.key"

# define the tls certificate and private key file paths.
# if these files exist, the application can run over https for local tls testing.
CERT_FILE = BASE_DIR / "cert.pem"
TLS_KEY_FILE = BASE_DIR / "key.pem"

# define the session cookie name used in the user's browser.
SESSION_COOKIE_NAME = "session_token"

# define how long a session can remain inactive before it expires, in seconds.
# 1800 seconds = 30 minutes.
SESSION_TIMEOUT_SECONDS = 1800

# define the maximum number of failed login attempts allowed from one ip address
# within a one-minute window before rate limiting is triggered.
MAX_LOGIN_ATTEMPTS_PER_IP_PER_MIN = 10

# define how many failed password attempts a user account is allowed
# before the account is temporarily locked.
MAX_FAILED_ATTEMPTS_PER_ACCOUNT = 5

# define how long an account remains locked after too many failed attempts.
# this value is measured in minutes.
ACCOUNT_LOCK_MINUTES = 15

# define which file extensions users are allowed to upload.
# this is the first layer of file-upload validation.
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx"}

# define which mime types are allowed for each supported extension.
# this is an additional validation layer so the application does not
# rely only on the file extension written in the filename.
ALLOWED_MIME_TYPES = {
    "pdf": {"application/pdf"},
    "txt": {"text/plain"},
    "docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    },
}

# define the maximum file size allowed for uploads.
# 10 * 1024 * 1024 bytes = 10 mb.
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

# load the flask secret from an environment variable if one is provided.
# otherwise, use a development fallback value.
#
# in a real production deployment, this value should always come from a secure source
# and should never be left as the default development string.
FLASK_SECRET = os.getenv("FLASK_SECRET", "dev-only-change-me")

# load the current app environment from an environment variable.
# if none is provided, default to "development".
ENVIRONMENT = os.getenv("APP_ENV", "development")

# enable debug mode only when the app environment is development.
DEBUG = ENVIRONMENT == "development"

# optionally force all traffic to use https when the environment variable is set.
# this reads the value as a string and treats "true" as enabled.
#
# examples:
# - force_https=false  -> false
# - force_https=true   -> true
#
# this is helpful because it lets you turn https enforcement on or off
# without changing the code itself.
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "false").lower() == "true"