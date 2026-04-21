import time

import app as bear_app
from tests.helpers import BearShareTestCase


class TestSessions(BearShareTestCase):
    # these tests verify logout invalidation and session expiration.

    def setUp(self):
        super().setUp()
        self.register_user("sessionuser", "session@example.com")

    def test_logout_invalidates_session(self):
        self.login_user("sessionuser")
        response1 = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response1.status_code, 200)

        self.logout_user()

        response2 = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response2.status_code, 302)
        self.assertIn("/login", response2.location)

    def test_session_expires_after_timeout(self):
        # make the session timeout very short for this test.
        bear_app.session_manager.timeout = 1

        self.login_user("sessionuser")
        time.sleep(1.2)

        response = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)