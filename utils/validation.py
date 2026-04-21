# this module contains input-validation helper functions used throughout the application.
# it is responsible for checking:
# - whether usernames follow the allowed format
# - whether email addresses look valid
# - whether passwords meet the strength policy
# - whether uploaded filenames use allowed extensions
# - whether filenames are safely sanitized before storage
# - whether text input falls within an allowed length range
# - whether uploaded mime types match the allowed file types
# - whether uploaded file contents match the expected file signature

import re
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename
from config import ALLOWED_EXTENSIONS, ALLOWED_MIME_TYPES

# this regular expression defines the allowed username format.
# usernames must:
# - be 3 to 20 characters long
# - contain only letters, numbers, and underscores
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def validate_username(username: str) -> bool:
    # check whether a username matches the allowed pattern exactly.
    #
    # fullmatch means the entire string must follow the rule,
    # not just part of it.
    #
    # if username is none or empty, "username or ''" makes sure
    # the function still works safely.
    return bool(USERNAME_REGEX.fullmatch(username or ""))


def validate_email_address(email: str) -> bool:
    # check whether an email address has a valid format.
    #
    # the email_validator library performs structured email validation.
    # check_deliverability=False means the function checks format only,
    # not whether the address can actually receive mail.
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        # if the email format is invalid, return false.
        return False


def validate_password_strength(password: str):
    # check whether a password meets the application's security policy.
    #
    # the function returns:
    # - (true, "") if the password is strong enough
    # - (false, specific_error_message) if the password fails a rule
    #
    # rules enforced here:
    # - at least 12 characters
    # - at least one uppercase letter
    # - at least one lowercase letter
    # - at least one number
    # - at least one special character from !@#$%^&*

    if len(password) < 12:
        return False, "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include a lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include a number."
    if not re.search(r"[!@#$%^&*]", password):
        return False, "Password must include a special character."

    # if all checks pass, the password is considered strong enough.
    return True, ""


def allowed_file(filename: str) -> bool:
    # check whether a filename has an extension and whether that extension
    # is in the allowed list defined in config.py.
    #
    # this is the first layer of file-upload filtering.

    # reject filenames with no dot because they do not have a usable extension.
    if "." not in filename:
        return False

    # extract the extension and convert it to lowercase.
    ext = filename.rsplit(".", 1)[1].lower()

    # return true only if the extension is explicitly allowed.
    return ext in ALLOWED_EXTENSIONS


def sanitize_filename(filename: str) -> str:
    # convert a user-supplied filename into a safer version.
    #
    # werkzeug's secure_filename removes or replaces unsafe characters
    # so that filenames do not contain problematic paths or symbols.
    return secure_filename(filename)


def validate_text_length(value: str, min_len: int = 1, max_len: int = 255) -> bool:
    # check whether a text value is within an acceptable length range.
    #
    # parameters:
    # - value: the text to check
    # - min_len: minimum allowed length after stripping whitespace
    # - max_len: maximum allowed length after stripping whitespace
    #
    # this helps reject empty or excessively long input values.

    if value is None:
        return False

    return min_len <= len(value.strip()) <= max_len


def get_file_extension(filename: str) -> str:
    # return the lowercase extension from a filename.
    # if there is no dot in the filename, return an empty string.
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def allowed_mime_type(filename: str, mimetype: str) -> bool:
    # check whether the uploaded mime type is allowed for the file's extension.
    #
    # this is a second layer of upload validation.
    # for example, a file named ".pdf" should not claim to be plain text.

    # get the file extension from the filename.
    ext = get_file_extension(filename)

    # reject the file if the extension is missing or not recognized
    # in the mime-type allowlist.
    if not ext or ext not in ALLOWED_MIME_TYPES:
        return False

    # return true only if the reported mime type is allowed for that extension.
    return mimetype in ALLOWED_MIME_TYPES[ext]


def file_signature_matches(filename: str, file_bytes: bytes) -> bool:
    # check whether the actual file content matches what the extension claims it is.
    #
    # this is an additional upload-hardening step.
    # it helps prevent someone from renaming one file type to look like another.
    #
    # examples:
    # - a real pdf should begin with "%pdf-"
    # - a real docx file is a zip-based format and should begin with "pk"
    # - a txt file should be decodable as utf-8 text

    ext = get_file_extension(filename)

    if ext == "pdf":
        # pdf files begin with the magic bytes "%pdf-"
        return file_bytes.startswith(b"%PDF-")

    if ext == "txt":
        # for text files, try decoding as utf-8.
        # if decoding works, treat it as valid text.
        try:
            file_bytes.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    if ext == "docx":
        # docx files are actually zip containers internally,
        # so they usually begin with the bytes "pk".
        return file_bytes.startswith(b"PK")

    # if the extension is not one of the supported types,
    # fail the signature check by default.
    return False