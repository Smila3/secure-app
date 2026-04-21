from io import BytesIO

from utils import document_service
from tests.helpers import BearShareTestCase


class TestUploads(BearShareTestCase):
    # these tests verify upload validation for good files and bad files.

    def setUp(self):
        super().setUp()
        self.register_user("owner", "owner@example.com")
        self.login_user("owner")

    def test_valid_pdf_upload(self):
        response = self.client.post(
            "/upload",
            data={
                "document": (BytesIO(b"%PDF-1.4\ntest pdf content"), "sample.pdf"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)

        documents = document_service.load_documents()
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0]["original_name"], "sample.pdf")

    def test_reject_bad_extension(self):
        response = self.client.post(
            "/upload",
            data={
                "document": (BytesIO(b"fake image bytes"), "malicious.jpg"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        documents = document_service.load_documents()
        self.assertEqual(len(documents), 0)

    def test_reject_empty_file(self):
        response = self.client.post(
            "/upload",
            data={
                "document": (BytesIO(b""), "empty.pdf"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        documents = document_service.load_documents()
        self.assertEqual(len(documents), 0)

    def test_reject_bad_signature(self):
        # this file is named as a pdf but does not start with the pdf signature.
        response = self.client.post(
            "/upload",
            data={
                "document": (BytesIO(b"\xff\xd8\xff\xe0fakejpg"), "not_really.pdf"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        documents = document_service.load_documents()
        self.assertEqual(len(documents), 0)