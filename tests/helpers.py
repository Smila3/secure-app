import tempfile
import unittest
from pathlib import Path

import app as bear_app
import config
from utils import auth, session_manager, document_service, logger, crypto_utils


class BearShareTestCase(unittest.TestCase):
    # this base test class creates a temporary test environment for each test.
    # it redirects the app's data, logs, encrypted files, and key file into a
    # temporary folder so tests do not modify your real project files.

    def setUp(self):
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir_obj.name)

        self.data_dir = self.base_dir / "data"
        self.logs_dir = self.base_dir / "logs"
        self.encrypted_dir = self.base_dir / "encrypted_files"
        self.secret_key_file = self.base_dir / "secret.key"

        self.users_file = self.data_dir / "users.json"
        self.sessions_file = self.data_dir / "sessions.json"
        self.documents_file = self.data_dir / "documents.json"
        self.shares_file = self.data_dir / "shares.json"
        self.audit_file = self.data_dir / "audit.json"
        self.failed_logins_file = self.data_dir / "failed_logins.json"

        self.security_log_file = self.logs_dir / "security.log"
        self.access_log_file = self.logs_dir / "access.log"

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)

        # patch config module values
        config.DATA_DIR = self.data_dir
        config.LOG_DIR = self.logs_dir
        config.ENCRYPTED_DIR = self.encrypted_dir
        config.SECRET_KEY_FILE = self.secret_key_file

        config.USERS_FILE = self.users_file
        config.SESSIONS_FILE = self.sessions_file
        config.DOCUMENTS_FILE = self.documents_file
        config.SHARES_FILE = self.shares_file
        config.AUDIT_FILE = self.audit_file
        config.FAILED_LOGINS_FILE = self.failed_logins_file

        config.SECURITY_LOG_FILE = self.security_log_file
        config.ACCESS_LOG_FILE = self.access_log_file

        # patch imported constants inside modules that copied config values at import time
        bear_app.DATA_DIR = self.data_dir
        bear_app.LOG_DIR = self.logs_dir
        bear_app.ENCRYPTED_DIR = self.encrypted_dir
        bear_app.FORCE_HTTPS = False

        auth.USERS_FILE = self.users_file
        auth.FAILED_LOGINS_FILE = self.failed_logins_file

        session_manager.SESSIONS_FILE = self.sessions_file

        document_service.DOCUMENTS_FILE = self.documents_file
        document_service.SHARES_FILE = self.shares_file
        document_service.AUDIT_FILE = self.audit_file
        document_service.ENCRYPTED_DIR = self.encrypted_dir

        crypto_utils.SECRET_KEY_FILE = self.secret_key_file

        
        # rebuild loggers so logs go into the temp folder
        logger.security_logger = logger._build_logger(
            f"test_security_logger_{id(self)}",
            self.security_log_file,
        )
        logger.access_logger = logger._build_logger(
            f"test_access_logger_{id(self)}",
            self.access_log_file,
        )

        # rebuild the session manager and encrypted storage using test paths
        bear_app.session_manager = session_manager.SessionManager()
        bear_app.encrypted_storage = crypto_utils.EncryptedStorage(self.secret_key_file)

        # initialize the required json files/folders in the temp environment
        bear_app.initialize_project_files()

        bear_app.app.config["TESTING"] = True
        self.client = bear_app.app.test_client()

    def tearDown(self):
        self.temp_dir_obj.cleanup()

    def register_user(
        self,
        username,
        email,
        password="ValidPassword1!",
        confirm_password="ValidPassword1!",
        account_type="user",
    ):
        return self.client.post(
            "/register",
            data={
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": confirm_password,
                "account_type": account_type,
            },
            follow_redirects=True,
        )

    def login_user(self, username, password="ValidPassword1!"):
        return self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
            },
            follow_redirects=True,
        )

    def logout_user(self):
        return self.client.post("/logout", follow_redirects=True)

    def first_document_id(self):
        documents = document_service.load_documents()
        if not documents:
            return None
        return documents[0]["id"]