# this module manages login sessions for the application.
# instead of relying on flask's default session system alone,
# this project stores session information in a json file so that
# session data can be tracked and validated directly.
#
# this class is responsible for:
# - creating new session tokens after login
# - saving session metadata to disk
# - validating whether a session is still active
# - expiring sessions after inactivity
# - destroying sessions during logout

import secrets
import time
from flask import request
from config import SESSIONS_FILE, SESSION_TIMEOUT_SECONDS
from utils.file_store import load_json, save_json


class SessionManager:
    # this class provides helper methods for working with user sessions.
    # each session is identified by a randomly generated token.
    # the token maps to metadata such as:
    # - user id
    # - time created
    # - last activity time
    # - ip address
    # - user agent

    def __init__(self, timeout=SESSION_TIMEOUT_SECONDS):
        # store the session timeout length.
        # this controls how long a session can remain inactive before expiring.
        self.timeout = timeout

    def load_sessions(self):
        # load the session dictionary from the sessions json file.
        # if the file does not exist or is empty, return an empty dictionary.
        return load_json(SESSIONS_FILE, {})

    def save_sessions(self, sessions):
        # save the full session dictionary back to the sessions json file.
        save_json(SESSIONS_FILE, sessions)

    def create_session(self, user_id: str):
        # create a new session for a successfully authenticated user.
        #
        # parameters:
        # - user_id: the id of the user who just logged in
        #
        # returns:
        # - a random session token that can be stored in the browser cookie

        # load the existing session records.
        sessions = self.load_sessions()

        # generate a cryptographically secure random token.
        # token_urlsafe(32) creates a string that is hard to guess
        # and safe to use in cookies and urls.
        token = secrets.token_urlsafe(32)

        # create the session record for this token.
        sessions[token] = {
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),

            # store the ip address that created the session.
            # even if the app does not fully enforce ip binding,
            # this is useful for logging and future security checks.
            "ip_address": request.remote_addr,

            # store the user-agent string from the browser.
            # this can also help with auditing or future session hardening.
            "user_agent": request.headers.get("User-Agent", ""),
        }

        # save the updated session dictionary to disk.
        self.save_sessions(sessions)

        # return the session token so it can be sent to the user's browser.
        return token

    def validate_session(self, token: str):
        # check whether a session token is valid and still active.
        #
        # parameters:
        # - token: the session token from the user's cookie
        #
        # returns:
        # - the session record if the token is valid
        # - none if the token does not exist or has expired

        # load all stored sessions and look up the one matching this token.
        sessions = self.load_sessions()
        session = sessions.get(token)

        # if the token is not found, the session is invalid.
        if not session:
            return None

        # check whether the session has been inactive for longer than the timeout.
        # if so, destroy it and reject it.
        if time.time() - session["last_activity"] > self.timeout:
            self.destroy_session(token)
            return None

        # if the session is still valid, update its last activity time
        # to show that the user is actively using the application.
        session["last_activity"] = time.time()
        sessions[token] = session
        self.save_sessions(sessions)

        # return the valid session record.
        return session

    def destroy_session(self, token: str):
        # remove a session token from storage.
        #
        # this is used during logout and session expiration so that
        # the session can no longer be used for authentication.

        # load the current sessions.
        sessions = self.load_sessions()

        # if the token exists, remove it and save the updated session store.
        if token in sessions:
            del sessions[token]
            self.save_sessions(sessions)