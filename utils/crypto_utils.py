# this module handles encryption and decryption for uploaded files.
# instead of storing files in plain text on disk, the application uses
# symmetric encryption so that file contents are protected at rest.

from pathlib import Path
from cryptography.fernet import Fernet
from config import SECRET_KEY_FILE


class EncryptedStorage:
    # this class is a small wrapper around the fernet encryption system.
    # it is responsible for:
    # - loading or creating the encryption key
    # - encrypting raw file bytes
    # - decrypting encrypted file bytes
    # - saving encrypted files to disk
    # - loading encrypted files from disk and decrypting them

    def __init__(self, key_file: Path = SECRET_KEY_FILE):
        # initialize the encrypted storage system.
        #
        # key_file points to the file where the symmetric encryption key is stored.
        # by default, it uses the key path defined in config.py.

        self.key_file = key_file

        # make sure the folder that will hold the key file exists.
        # parents=True allows python to create missing parent folders too.
        # exist_ok=True prevents an error if the folder already exists.
        self.key_file.parent.mkdir(parents=True, exist_ok=True)

        # if the key file already exists, reuse the saved key.
        # this is important because encrypted files can only be decrypted
        # with the same key that was used to encrypt them.
        if self.key_file.exists():
            self.key = self.key_file.read_bytes()
        else:
            # if no key file exists yet, generate a new one.
            # this key will be used for all file encryption and decryption.
            self.key = Fernet.generate_key()

            # save the new key to disk so it can be reused later.
            self.key_file.write_bytes(self.key)

        # create a fernet cipher object using the loaded or newly generated key.
        # this cipher object provides the actual encrypt and decrypt methods.
        self.cipher = Fernet(self.key)

    def encrypt_bytes(self, raw_bytes: bytes) -> bytes:
        # take plain file bytes and return an encrypted version of them.
        # this is used before saving uploaded files to disk.
        return self.cipher.encrypt(raw_bytes)

    def decrypt_bytes(self, encrypted_bytes: bytes) -> bytes:
        # take encrypted file bytes and return the original plain bytes.
        # this is used when an authorized user views or downloads a file.
        return self.cipher.decrypt(encrypted_bytes)

    def save_encrypted_file(self, path: Path, raw_bytes: bytes):
        # encrypt raw file bytes and save the encrypted result to the given path.
        #
        # path is where the encrypted file should be stored on disk.
        # raw_bytes is the original uploaded file content before encryption.

        # first encrypt the file contents.
        encrypted = self.encrypt_bytes(raw_bytes)

        # make sure the folder where the encrypted file will be stored exists.
        path.parent.mkdir(parents=True, exist_ok=True)

        # write the encrypted bytes to disk.
        path.write_bytes(encrypted)

    def load_decrypted_file(self, path: Path) -> bytes:
        # load an encrypted file from disk and return its decrypted contents.
        #
        # this is used when the application needs to serve a file back to
        # an authorized user for viewing or downloading.

        # read the encrypted bytes from the file.
        encrypted = path.read_bytes()

        # decrypt the file contents and return the original bytes.
        return self.decrypt_bytes(encrypted)