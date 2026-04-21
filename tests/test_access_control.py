from io import BytesIO

from utils import document_service, auth
from tests.helpers import BearShareTestCase


class TestAccessControl(BearShareTestCase):
    # these tests verify that only authorized users can access private documents.

    def setUp(self):
        super().setUp()

        self.register_user("owner", "owner@example.com")
        self.register_user("otheruser", "other@example.com")
        self.register_user("guest1", "guest1@example.com", account_type="guest")

        # owner uploads one private document
        self.login_user("owner")
        self.client.post(
            "/upload",
            data={
                "document": (BytesIO(b"%PDF-1.4\nowner file"), "ownerfile.pdf"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.doc_id = self.first_document_id()
        self.logout_user()

    def test_unshared_user_cannot_download_private_file(self):
        self.login_user("otheruser")
        response = self.client.get(f"/download/{self.doc_id}", follow_redirects=False)
        self.assertEqual(response.status_code, 403)

    def test_owner_can_share_with_guest_as_viewer(self):
        self.login_user("owner")
        response = self.client.post(
            f"/share/{self.doc_id}",
            data={
                "username": "guest1",
                "role": "viewer",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        shares = document_service.load_shares()
        guest = auth.find_user_by_username("guest1")
        self.assertEqual(shares[self.doc_id][guest["id"]], "viewer")

    def test_guest_cannot_receive_editor_access(self):
        self.login_user("owner")
        response = self.client.post(
            f"/share/{self.doc_id}",
            data={
                "username": "guest1",
                "role": "editor",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        shares = document_service.load_shares()
        guest = auth.find_user_by_username("guest1")
        self.assertNotEqual(shares.get(self.doc_id, {}).get(guest["id"]), "editor")