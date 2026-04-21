from utils import auth
from tests.helpers import BearShareTestCase


class TestAuthentication(BearShareTestCase):
    # these tests verify registration, login, lockout, and password change behavior.

    def test_register_success(self):
        response = self.register_user("alice", "alice@example.com")
        self.assertEqual(response.status_code, 200)

        users = auth.load_users()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "alice")
        self.assertNotEqual(users[0]["password_hash"], "ValidPassword1!")

    def test_register_rejects_weak_password(self):
        response = self.register_user(
            "bob",
            "bob@example.com",
            password="weak",
            confirm_password="weak",
        )
        self.assertEqual(response.status_code, 200)

        users = auth.load_users()
        self.assertEqual(len(users), 0)

    def test_login_success(self):
        self.register_user("carol", "carol@example.com")
        response = self.login_user("carol", "ValidPassword1!")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"dashboard", response.data.lower())

    def test_account_lockout_after_repeated_failures(self):
        self.register_user("dave", "dave@example.com")

        for _ in range(auth.MAX_FAILED_ATTEMPTS_PER_ACCOUNT):
            self.login_user("dave", "WrongPassword1!")

        users = auth.load_users()
        user = next(u for u in users if u["username"] == "dave")
        self.assertIsNotNone(user["locked_until"])

    def test_change_password_success(self):
        self.register_user("erin", "erin@example.com")
        users = auth.load_users()
        user = next(u for u in users if u["username"] == "erin")

        ok, message = auth.change_password(
            user["id"],
            "ValidPassword1!",
            "NewValidPassword1!",
            "NewValidPassword1!",
        )

        self.assertTrue(ok)
        self.assertEqual(message, "Password changed successfully.")

        ok2, _, _ = auth.authenticate_user("erin", "NewValidPassword1!", "127.0.0.1")
        self.assertTrue(ok2)