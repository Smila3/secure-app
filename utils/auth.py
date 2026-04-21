# this module handles user authentication and account-related security features.
# it is responsible for:
# - loading and saving user account data
# - finding users by username or email
# - hashing and verifying passwords
# - registering new users
# - authenticating logins
# - enforcing account lockout after repeated failures
# - enforcing ip-based rate limiting for login abuse
# - changing a user's password

import time
import uuid
import bcrypt
from config import (
    USERS_FILE,
    MAX_FAILED_ATTEMPTS_PER_ACCOUNT,
    ACCOUNT_LOCK_MINUTES,
    FAILED_LOGINS_FILE,
    MAX_LOGIN_ATTEMPTS_PER_IP_PER_MIN,
)
from utils.file_store import load_json, save_json
from utils.validation import (
    validate_username,
    validate_email_address,
    validate_password_strength,
)
from utils.logger import log_security_event


def load_users():
    # load the list of users from the users json file.
    # if the file does not exist or is empty, return an empty list.
    return load_json(USERS_FILE, [])


def save_users(users):
    # save the full list of user dictionaries back to the users json file.
    # this is used after registration, login updates, password changes, and role changes.
    save_json(USERS_FILE, users)


def find_user_by_username(username: str):
    # search through all users and return the first user whose username matches.
    # if no matching username is found, return none.
    users = load_users()
    return next((u for u in users if u["username"] == username), None)


def find_user_by_email(email: str):
    # search through all users and return the first user whose email matches.
    # this helps prevent duplicate account registration with the same email.
    # if no matching email is found, return none.
    users = load_users()
    return next((u for u in users if u["email"] == email), None)


def hash_password(password: str) -> str:
    # create a bcrypt salt and use it to hash the given password.
    # bcrypt is intentionally slow, which helps protect against brute-force attacks
    # if password hashes are ever exposed.
    #
    # rounds=12 controls the computational cost of hashing.
    # the result is converted from bytes to a string so it can be stored in json.
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    # compare a plain-text password entered by the user against the stored bcrypt hash.
    # this returns true if the password matches and false otherwise.
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def register_user(
    username: str,
    email: str,
    password: str,
    confirm_password: str,
    ip_address: str,
    account_type: str,
):
    # create a new user account after validating all registration inputs.
    #
    # this function returns:
    # - true and a success message if registration works
    # - false and an error message if any validation fails

    # before doing normal registration checks, make sure this ip address
    # has not already made too many recent failed login attempts.
    # this helps prevent automated abuse from a single source.
    if too_many_ip_attempts(ip_address):
        log_security_event(
            f"REGISTER_RATE_LIMIT_TRIGGERED username={username} ip={ip_address}",
            "warning",
        )
        return False, "Too many login attempts from this IP. Time to hibernate for a bit!"

    # only allow the supported account types.
    # admin accounts are intentionally not created through self-registration.
    if account_type not in {"user", "guest"}:
        return False, "Please select a valid account type."

    # validate the username format using the validation module.
    if not validate_username(username):
        return False, "Your username is invalid! Use 3–20 letters, numbers, or underscores."

    # validate the email address format.
    if not validate_email_address(email):
        return False, "Your email address is invalid!"

    # check password strength rules such as length and complexity.
    valid_pw, pw_msg = validate_password_strength(password)
    if not valid_pw:
        return False, pw_msg

    # confirm that the password confirmation matches the original password.
    if password != confirm_password:
        return False, "The passwords do not match."

    # prevent duplicate usernames.
    if find_user_by_username(username):
        return False, "This username already exists."

    # prevent duplicate email addresses.
    if find_user_by_email(email):
        return False, "This email already exists."

    # the selected account type becomes the user's role.
    role = account_type

    # load the existing users so the new user can be appended.
    users = load_users()

    # build the new user record.
    # each user gets:
    # - a unique id
    # - username and email
    # - hashed password
    # - assigned role
    # - counters for failed login attempts and lockout
    # - account creation timestamp
    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": time.time(),
    }

    # add the new user to the list and save it.
    users.append(user)
    save_users(users)

    # report success to the caller.
    return True, f"Welcome to the den! Your role is {role}."


def is_locked(user: dict) -> bool:
    # check whether a user's account is currently locked.
    #
    # locked_until stores the time when the lock expires.
    # if locked_until is in the future, the account is still locked.
    locked_until = user.get("locked_until")
    return locked_until is not None and time.time() < locked_until


def authenticate_user(username: str, password: str, ip_address: str):
    # verify a login attempt.
    #
    # this function returns a tuple:
    # - (true, success_message, user_dict) if login succeeds
    # - (false, error_message, none) if login fails

    # load all user accounts so we can search for the one trying to log in.
    users = load_users()

    # first check whether this ip address has already made too many recent failed attempts.
    # this adds a second layer of abuse protection beyond per-account lockout.
    if too_many_ip_attempts(ip_address):
        log_security_event(
            f"RATE_LIMIT_TRIGGERED username={username} ip={ip_address} reason=too_many_login_attempts",
            "warning",
        )
        return False, "Too many login attempts from this IP. It's time to cool off in the snow!", None

    # try to find the user account by username.
    user = next((u for u in users if u["username"] == username), None)

    # if the username does not exist, record a failed ip attempt and return a generic error.
    # the generic message avoids revealing whether the username exists.
    if not user:
        record_failed_ip_attempt(ip_address)
        return False, "Your credentials don't match our bear records. You have an invalid username or password.", None

    # if the account is currently locked, do not even attempt password verification.
    if is_locked(user):
        return False, "This account is hibernating for a bit and is temporarily locked.", None

    # verify the password against the stored hash.
    if not verify_password(password, user["password_hash"]):
        # record the failed ip attempt for rate limiting.
        record_failed_ip_attempt(ip_address)

        # increase the user's failed-attempt counter.
        user["failed_attempts"] += 1

        # if the user has now reached the account failure threshold,
        # set a lockout expiration time.
        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS_PER_ACCOUNT:
            user["locked_until"] = time.time() + (ACCOUNT_LOCK_MINUTES * 60)
            log_security_event(
                f"ACCOUNT_LOCKED username={username} ip={ip_address} reason=too_many_failed_attempts",
                "error",
            )

        # save the updated failure count and possible lockout time.
        save_users(users)

        # return a generic failure message.
        return False, "Your credentials don't match our bear records. You have an invalid username or password.", None

    # if we get here, the password was correct.
    # reset failed-attempt tracking for this account.
    user["failed_attempts"] = 0
    user["locked_until"] = None
    save_users(users)

    # return the authenticated user record.
    return True, "Login successful.", user


def load_failed_logins():
    # load the dictionary that tracks failed login timestamps by ip address.
    # if the file is missing or empty, return an empty dictionary.
    return load_json(FAILED_LOGINS_FILE, {})


def save_failed_logins(data):
    # save the failed-login tracking dictionary back to disk.
    save_json(FAILED_LOGINS_FILE, data)


def record_failed_ip_attempt(ip_address: str):
    # record a failed login attempt for a specific ip address.
    #
    # this function only keeps timestamps from the last 60 seconds.
    # older attempts are removed so the rate limit is based on recent behavior.

    failed = load_failed_logins()
    now = time.time()

    # get the current list of timestamps for this ip, or an empty list if none exist.
    attempts = failed.get(ip_address, [])

    # keep only timestamps from the last minute.
    attempts = [t for t in attempts if now - t <= 60]

    # add the new failed-attempt timestamp.
    attempts.append(now)

    # store the updated list back under this ip and save it.
    failed[ip_address] = attempts
    save_failed_logins(failed)


def too_many_ip_attempts(ip_address: str) -> bool:
    # check whether an ip address has exceeded the allowed number of failed attempts
    # within the last 60 seconds.

    failed = load_failed_logins()
    now = time.time()

    # get the current timestamps for this ip.
    attempts = failed.get(ip_address, [])

    # remove timestamps older than one minute.
    attempts = [t for t in attempts if now - t <= 60]

    # save the cleaned list back to disk so stale entries do not build up over time.
    failed[ip_address] = attempts
    save_failed_logins(failed)

    # return true if the number of recent attempts meets or exceeds the configured limit.
    return len(attempts) >= MAX_LOGIN_ATTEMPTS_PER_IP_PER_MIN


def clear_failed_ip_attempts(ip_address: str):
    # clear the stored failed-attempt history for one ip address.
    # this helper can be useful for testing or manual reset behavior.
    failed = load_failed_logins()
    if ip_address in failed:
        failed[ip_address] = []
        save_failed_logins(failed)


def change_password(user_id: str, current_password: str, new_password: str, confirm_password: str):
    # change a user's password after verifying identity and checking password rules.
    #
    # this function returns:
    # - (true, success_message) if the password change succeeds
    # - (false, error_message) if the change fails for any reason

    # first make sure the new password matches the confirmation field.
    if new_password != confirm_password:
        return False, "New passwords do not match."

    # validate the new password against the password-strength policy.
    valid_pw, pw_msg = validate_password_strength(new_password)
    if not valid_pw:
        return False, pw_msg

    # load all users and find the account that matches the provided user id.
    users = load_users()
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        return False, "User not found."

    # verify that the user entered their current password correctly.
    # this prevents someone with temporary access to an active session
    # from changing the password without knowing the old one.
    if not verify_password(current_password, user["password_hash"]):
        return False, "Current password is incorrect."

    # prevent the user from reusing the exact same password.
    if verify_password(new_password, user["password_hash"]):
        return False, "Your new password cannot be the same as your current password."

    # hash the new password and replace the old hash.
    user["password_hash"] = hash_password(new_password)

    # reset failed login attempts after a successful password change,
    # since the account state is being refreshed.
    user["failed_attempts"] = 0

    # save the updated user list to disk.
    save_users(users)

    return True, "Password changed successfully."