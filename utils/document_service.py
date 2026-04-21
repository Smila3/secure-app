# this module handles most of the document-related logic for the application.
# it is responsible for:
# - loading and saving document metadata
# - loading and saving document sharing permissions
# - loading and saving audit records
# - creating new document records
# - checking who can download, edit, or delete a document
# - sharing documents with other users
# - downgrading permissions when a user becomes a guest
# - creating new versions of documents
# - soft deleting documents
# - managing special global documents

import mimetypes
import time
import uuid
from pathlib import Path

from config import DOCUMENTS_FILE, SHARES_FILE, AUDIT_FILE, ENCRYPTED_DIR
from utils.file_store import load_json, save_json
from utils.validation import sanitize_filename
from utils.auth import find_user_by_username, load_users


def load_documents():
    # load all document metadata from the documents json file.
    # if the file is missing or empty, return an empty list.
    return load_json(DOCUMENTS_FILE, [])


def save_documents(documents):
    # save the full document metadata list back to the documents json file.
    save_json(DOCUMENTS_FILE, documents)


def load_shares():
    # load the dictionary that stores sharing permissions.
    # this usually maps document ids to user ids and permission roles.
    return load_json(SHARES_FILE, {})


def save_shares(shares):
    # save the full sharing-permissions dictionary back to the shares json file.
    save_json(SHARES_FILE, shares)


def load_audit():
    # load the audit history from the audit json file.
    # audit entries record important document-related actions for accountability.
    return load_json(AUDIT_FILE, [])


def save_audit(audit):
    # save the updated audit history back to disk.
    save_json(AUDIT_FILE, audit)


def create_audit_event(doc_id: str, user_id: str, action: str, version=None, details=None):
    # create a new audit entry that records something important that happened
    # to a document, such as an upload, share, delete, or permission downgrade.
    #
    # parameters:
    # - doc_id: the document involved in the action
    # - user_id: the user who performed the action
    # - action: a short label such as "upload" or "delete"
    # - version: optional document version number
    # - details: optional dictionary with extra information

    audit = load_audit()

    # build the basic audit record with a unique id and timestamp.
    entry = {
        "event_id": str(uuid.uuid4()),
        "doc_id": doc_id,
        "user_id": user_id,
        "action": action,
        "timestamp": time.time(),
    }

    # only include version if one was provided.
    if version is not None:
        entry["version"] = version

    # only include extra details if they were provided.
    if details is not None:
        entry["details"] = details

    # add the new record to the audit list and save it.
    audit.append(entry)
    save_audit(audit)


def create_document_record(owner_id: str, original_name: str):
    # create a brand-new document metadata record when a user uploads a file.
    #
    # this does not itself encrypt or write the file contents.
    # instead, it prepares the metadata that points to where the encrypted file
    # will be stored and who owns it.

    documents = load_documents()

    # create a unique id for the document.
    doc_id = str(uuid.uuid4())

    # sanitize the original filename so unsafe characters do not get stored or used.
    safe_name = sanitize_filename(original_name)

    # extract the file extension from the sanitized filename.
    ext = safe_name.rsplit(".", 1)[1].lower()

    # build the stored encrypted filename.
    # version 1 is used for the original upload.
    stored_name = f"{doc_id}_v1.{ext}.enc"

    # create the document metadata entry.
    doc = {
        "id": doc_id,
        "owner_id": owner_id,
        "original_name": safe_name,
        "stored_name": stored_name,
        "created_at": time.time(),
        "latest_version": 1,
        "deleted": False,
        "mime_type": mimetypes.guess_type(safe_name)[0] or "application/octet-stream",
    }

    # save the new document metadata.
    documents.append(doc)
    save_documents(documents)

    # create the sharing entry for this document and make the uploader the owner.
    shares = load_shares()
    shares.setdefault(doc_id, {})
    shares[doc_id][owner_id] = "owner"
    save_shares(shares)

    # record the initial upload in the audit trail.
    create_audit_event(doc_id, owner_id, "UPLOAD", version=1)

    return doc


def get_document_by_id(doc_id: str):
    # return the document metadata for a specific document id,
    # but only if the document exists and has not been marked as deleted.
    documents = load_documents()
    return next(
        (d for d in documents if d["id"] == doc_id and not d.get("deleted", False)),
        None
    )


def user_document_role(doc_id: str, user_id: str):
    # look up what role a specific user has on a specific document.
    # possible roles include owner, editor, and viewer.
    shares = load_shares()
    return shares.get(doc_id, {}).get(user_id)


def get_user_by_id(user_id: str):
    # load all users and return the one whose id matches the given user id.
    # if no matching user is found, return none.
    users = load_users()
    return next((u for u in users if u["id"] == user_id), None)


def is_owner(doc_id: str, user_id: str) -> bool:
    # check whether the user is treated as the owner of the document.
    #
    # admins are allowed to act as if they are owners for management purposes.
    # otherwise, the user must explicitly have the "owner" role on the document.

    user = get_user_by_id(user_id)
    if user and user.get("role") == "admin":
        return True

    return user_document_role(doc_id, user_id) == "owner"


def can_download(doc_id: str, user_id: str) -> bool:
    # check whether a user is allowed to download or access a document.
    #
    # admins can always access documents.
    # regular users must have one of the document roles that grants read access.

    user = get_user_by_id(user_id)
    if user and user.get("role") == "admin":
        return True

    role = user_document_role(doc_id, user_id)
    return role in {"owner", "editor", "viewer"}


def can_edit(doc_id: str, user_id: str) -> bool:
    # check whether a user is allowed to upload a new version of a document.
    #
    # admins can always edit.
    # otherwise, only owners and editors are allowed to update a document.

    user = get_user_by_id(user_id)
    if user and user.get("role") == "admin":
        return True

    role = user_document_role(doc_id, user_id)
    return role in {"owner", "editor"}


def can_create_content(user):
    # return true if the user is allowed to create content such as uploads.
    # admins and normal users can create content, but guests cannot.
    return user and user.get("role") in {"admin", "user"}


def can_view_all_content(user):
    # return true only if the user is an admin.
    # this is used when admins are allowed to see all documents in the system.
    return user and user.get("role") == "admin"


def downgrade_guest_permissions(user_id: str, admin_id: str = None):
    # downgrade a user's document permissions when they are changed to a guest account.
    #
    # guests are not allowed to keep editor access, so any "editor" role
    # for this user is changed to "viewer".
    #
    # parameters:
    # - user_id: the user being downgraded
    # - admin_id: optional id of the admin performing the change, used for auditing
    #
    # returns:
    # - a list of document ids whose permissions were changed

    shares = load_shares()
    changed_docs = []

    # loop through every document's permission list.
    for doc_id, permissions in shares.items():
        # if this user is currently an editor on this document,
        # downgrade them to viewer.
        if permissions.get(user_id) == "editor":
            permissions[user_id] = "viewer"
            changed_docs.append(doc_id)

            # if we know which admin performed the change, record it in the audit log.
            if admin_id is not None:
                create_audit_event(
                    doc_id,
                    admin_id,
                    "PERMISSION_DOWNGRADE",
                    details={
                        "target_user_id": user_id,
                        "old_role": "editor",
                        "new_role": "viewer",
                        "reason": "User changed to guest",
                    },
                )

    # save the updated sharing permissions after all downgrades are complete.
    save_shares(shares)
    return changed_docs


def document_storage_path(stored_name: str) -> Path:
    # build and return the full filesystem path where an encrypted file is stored.
    return ENCRYPTED_DIR / stored_name


def share_document(doc_id: str, owner_id: str, target_username: str, role: str):
    # share a document with another user.
    #
    # this function checks:
    # - whether the requested role is valid
    # - whether the document exists
    # - whether the caller is the document owner
    # - whether the target user exists
    # - whether the owner is trying to share with themselves
    # - whether a guest is being incorrectly given editor access
    #
    # returns:
    # - (true, success_message) on success
    # - (false, error_message) on failure

    # only viewer and editor are valid share roles.
    if role not in {"viewer", "editor"}:
        return False, "Invalid role selected."

    # make sure the document exists and is not deleted.
    doc = get_document_by_id(doc_id)
    if not doc:
        return False, "This file may have wandered off into the woods. Document not found!"

    # only the real document owner can share the file.
    if doc["owner_id"] != owner_id:
        return False, "Paws off. Only the owner can share this document."

    # look up the user who is supposed to receive access.
    target_user = find_user_by_username(target_username)
    if not target_user:
        return False, "Target user does not exist."

    # prevent an owner from trying to share the document with themselves.
    if target_user["id"] == owner_id:
        return False, "You already own this document."

    # guests are only allowed to receive viewer access.
    if target_user.get("role") == "guest" and role == "editor":
        return False, "Guest accounts can only be assigned viewer access."

    # update the sharing table with the new permission.
    shares = load_shares()
    shares.setdefault(doc_id, {})
    shares[doc_id][target_user["id"]] = role
    save_shares(shares)

    # record the share action in the audit log.
    create_audit_event(
        doc_id,
        owner_id,
        "SHARE",
        details={
            "shared_with": target_user["username"],
            "shared_with_user_id": target_user["id"],
            "role": role,
        },
    )

    return True, f"Document shared with {target_username} as {role}."


def get_file_extension(filename: str) -> str:
    # return the lowercase file extension from a filename.
    # if the filename does not contain a dot, return an empty string.
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def update_document_version(doc_id: str, user_id: str, new_original_name: str):
    # update a document's metadata when a new version is uploaded.
    #
    # this function:
    # - finds the document
    # - increases its version number
    # - generates a new encrypted stored filename
    # - updates the visible original filename if needed
    # - updates the mime type
    # - records the version upload in the audit log
    #
    # it returns the updated document metadata, or none if the document is missing.

    documents = load_documents()
    doc = next(
        (d for d in documents if d["id"] == doc_id and not d.get("deleted", False)),
        None
    )

    # if the document does not exist or is deleted, stop here.
    if not doc:
        return None

    # create the next version number.
    new_version = doc["latest_version"] + 1

    # determine which file extension to use.
    # prefer the new uploaded filename if available; otherwise reuse the old one.
    ext = get_file_extension(new_original_name or doc["original_name"])
    if not ext:
        ext = get_file_extension(doc["original_name"])

    # build the new encrypted storage filename for this version.
    stored_name = f"{doc_id}_v{new_version}.{ext}.enc"

    # update the document metadata.
    doc["latest_version"] = new_version
    doc["stored_name"] = stored_name
    doc["original_name"] = sanitize_filename(new_original_name or doc["original_name"])
    doc["mime_type"] = mimetypes.guess_type(doc["original_name"])[0] or "application/octet-stream"

    # save the updated document list.
    save_documents(documents)

    # record the new version upload in the audit history.
    create_audit_event(
        doc_id,
        user_id,
        "NEW_VERSION_UPLOAD",
        version=new_version,
        details={
            "stored_name": stored_name,
            "original_name": doc["original_name"],
        },
    )

    return doc


def can_delete(doc_id: str, user_id: str) -> bool:
    # check whether a user is allowed to delete a document.
    #
    # admins can always delete.
    # otherwise, only the document owner can delete the file.

    user = get_user_by_id(user_id)
    if user and user.get("role") == "admin":
        return True

    doc = get_document_by_id(doc_id)
    if not doc:
        return False

    return doc["owner_id"] == user_id


def delete_document(doc_id: str, user_id: str):
    # soft delete a document.
    #
    # this does not erase the file from disk immediately.
    # instead, it marks the document as deleted so it no longer appears
    # in normal views and is treated as inaccessible by the application.
    #
    # returns:
    # - (true, success_message) if deletion succeeds
    # - (false, error_message) if deletion fails

    documents = load_documents()
    doc = next(
        (d for d in documents if d["id"] == doc_id and not d.get("deleted", False)),
        None
    )

    # fail if the document cannot be found or is already deleted.
    if not doc:
        return False, "This file may have wandered off into the woods. Document not found!"

    # fail if the user is not allowed to delete this document.
    if not can_delete(doc_id, user_id):
        return False, "Paws off! You do not have permission to delete this document."

    # mark the document as deleted and save the updated metadata.
    doc["deleted"] = True
    save_documents(documents)

    # record the delete action in the audit log.
    create_audit_event(
        doc_id,
        user_id,
        "DELETE",
        version=doc.get("latest_version"),
        details={
            "original_name": doc.get("original_name"),
            "stored_name": doc.get("stored_name"),
        },
    )

    return True, "Document deleted successfully."


def get_global_documents():
    # return all documents that have been marked as global
    # and have not been deleted.
    #
    # global documents are special documents intended to be managed by admins
    # and made broadly available through the application.
    documents = load_documents()
    return [d for d in documents if d.get("is_global", False) and not d.get("deleted", False)]


def create_global_document(original_name: str, admin_user_id: str):
    # create a new global document record.
    #
    # this is similar to create_document_record, but it marks the document
    # with is_global=true so the application can treat it differently.

    documents = load_documents()

    # generate a new unique document id.
    doc_id = str(uuid.uuid4())

    # sanitize the uploaded name and build the encrypted storage filename.
    safe_name = sanitize_filename(original_name)
    ext = safe_name.rsplit(".", 1)[1].lower()
    stored_name = f"{doc_id}_v1.{ext}.enc"

    # build the metadata record for the global document.
    doc = {
        "id": doc_id,
        "owner_id": admin_user_id,
        "original_name": safe_name,
        "stored_name": stored_name,
        "created_at": time.time(),
        "latest_version": 1,
        "deleted": False,
        "is_global": True,
        "mime_type": mimetypes.guess_type(safe_name)[0] or "application/octet-stream",
    }

    # save the new document metadata.
    documents.append(doc)
    save_documents(documents)

    # set the admin who created it as the owner in the sharing table.
    shares = load_shares()
    shares.setdefault(doc_id, {})
    shares[doc_id][admin_user_id] = "owner"
    save_shares(shares)

    # record the upload of the global document.
    create_audit_event(doc_id, admin_user_id, "UPLOAD_GLOBAL", version=1)
    return doc


def delete_global_document(doc_id: str, admin_user_id: str):
    # soft delete a global document.
    #
    # this function only succeeds if the document exists and is marked as global.
    # it returns true on success and false on failure.

    documents = load_documents()
    doc = next((d for d in documents if d["id"] == doc_id), None)

    # fail if the document does not exist or is not a global document.
    if not doc or not doc.get("is_global"):
        return False

    # mark the document as deleted and save the metadata.
    doc["deleted"] = True
    save_documents(documents)

    # record the delete action for auditing.
    create_audit_event(doc_id, admin_user_id, "DELETE_GLOBAL")
    return True