# this is the main flask application file for bearshare.
# it connects together the rest of the project and defines:
# - app configuration
# - startup behavior
# - request hooks
# - security headers
# - authentication routes
# - document routes
# - admin routes
# - password-change behavior
# - error handling
#
# in other words, this file is the central controller for the whole web app.

from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, make_response, g, flash, send_file, abort
)

from config import (
    FLASK_SECRET,
    TEMPLATE_DIR,
    STATIC_DIR,
    DATA_DIR,
    LOG_DIR,
    ENCRYPTED_DIR,
    SESSION_COOKIE_NAME,
    DEBUG,
    FORCE_HTTPS,
    CERT_FILE,
    TLS_KEY_FILE,
)

# import authentication helpers from the auth module.
# "change_password as update_user_password" renames the imported function locally
# so its purpose is clearer when used in this file.
from utils.auth import register_user, authenticate_user, load_users, save_users, change_password as update_user_password

# import the session manager, which creates and validates server-side sessions.
from utils.session_manager import SessionManager

# import logging helpers for security events and normal access/activity events.
from utils.logger import log_security_event, log_access_event

# import decorators and helper functions used for route protection and authorization.
from utils.decorators import (
    require_login,
    require_role,
    can_view_all_content,
    can_create_content,
)

# import the encryption helper used to store files in encrypted form on disk.
from utils.crypto_utils import EncryptedStorage

# import document-related helpers such as access checks, sharing, versioning, and deletion.
from utils.document_service import (
    create_document_record,
    get_document_by_id,
    can_download,
    can_edit,
    can_delete,
    document_storage_path,
    load_documents,
    load_shares,
    share_document,
    is_owner,
    downgrade_guest_permissions,
    update_document_version,
    delete_document,
    get_global_documents,
    create_global_document,
    delete_global_document,
)

# import file validation helpers used during upload and new-version upload.
from utils.validation import allowed_file, allowed_mime_type, file_signature_matches

# create the flask application object.
# template_folder and static_folder tell flask where to find html templates and static assets.
app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
)

# set the secret key used by flask for secure operations like flashing messages.
app.secret_key = FLASK_SECRET

# set the maximum allowed upload size to 10 mb.
# flask will reject requests larger than this limit.
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# create one session manager instance for handling logins and session validation.
session_manager = SessionManager()

# create one encrypted storage helper for encrypting and decrypting stored files.
encrypted_storage = EncryptedStorage()


def initialize_project_files():
    # create the important project folders if they do not already exist.
    #
    # these folders hold:
    # - persistent json data
    # - log files
    # - encrypted uploaded files
    DATA_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    ENCRYPTED_DIR.mkdir(exist_ok=True)

    # define the json files the application expects to exist at startup,
    # along with the default contents each file should have.
    required_files = {
        DATA_DIR / "users.json": "[]",
        DATA_DIR / "sessions.json": "{}",
        DATA_DIR / "documents.json": "[]",
        DATA_DIR / "shares.json": "{}",
        DATA_DIR / "audit.json": "[]",
        DATA_DIR / "failed_logins.json": "{}",
    }

    # if any required file is missing, create it with its default content.
    for filepath, default_content in required_files.items():
        if not filepath.exists():
            filepath.write_text(default_content, encoding="utf-8")


@app.before_request
def enforce_https():
    # this hook runs before every request.
    #
    # if force_https is enabled and the incoming request is not secure,
    # redirect the user to the https version of the same url.
    #
    # this helps make sure traffic uses tls when that feature is enabled.
    if FORCE_HTTPS and not request.is_secure:
        return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.before_request
def load_user():
    # this hook runs before every request and loads the currently logged-in user.
    #
    # it checks the session cookie, validates the session token,
    # and if valid, stores the full user record in flask's "g" object.
    #
    # g.user can then be used anywhere during the request to know who is logged in.
    g.user = None

    # read the session token from the browser cookie.
    token = request.cookies.get(SESSION_COOKIE_NAME)

    if token:
        # validate the session token using the session manager.
        session_data = session_manager.validate_session(token)

        if session_data:
            # if the session is valid, load all users and find the matching user record.
            users = load_users()
            g.user = next(
                (u for u in users if u["id"] == session_data["user_id"]),
                None
            )


@app.after_request
def set_cache_headers(response):
    # this hook runs after every request and adds cache-control headers.
    #
    # css files are allowed to be cached for faster repeat page loads.
    # html pages are marked as no-cache so the browser does not keep showing stale content.
    if response.mimetype == 'text/css':
        response.headers['Cache-Control'] = 'public, max-age=3600'
    elif response.mimetype == 'text/html':
        response.headers['Cache-Control'] = 'no-cache, public'
    return response


@app.after_request
def set_security_headers(response):
    # this hook runs after every request and adds security-related response headers.
    #
    # these headers help reduce risks such as:
    # - cross-site scripting
    # - clickjacking
    # - mime-type sniffing
    # - unwanted browser features
    # - insecure repeat access after https
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # only send hsts when the current request is actually secure.
    # hsts tells the browser to prefer https for future visits.
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


@app.route("/")
def index():
    # render the home page.
    # user=g.user lets the template know whether a user is logged in.
    return render_template("index.html", user=g.user)


@app.route("/register", methods=["GET", "POST"])
def register():
    # handle account registration.
    #
    # get requests show the registration page.
    # post requests process submitted registration data.
    if request.method == "POST":
        # collect form values from the registration form.
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        account_type = request.form.get("account_type", "").strip().lower()

        # pass the submitted values to the auth module.
        ok, message = register_user(
            username,
            email,
            password,
            confirm_password,
            request.remote_addr,
            account_type,
        )

        # if registration succeeds, log it, show a success message,
        # and send the user to the login page.
        if ok:
            log_security_event(
                f"REGISTER_SUCCESS username={username} ip={request.remote_addr}",
                "INFO",
            )
            flash(message, "success")
            return redirect(url_for("login"))

        # if registration fails, log the failure and re-render the form.
        log_security_event(
            f"REGISTER_FAIL username={username} ip={request.remote_addr} reason={message}",
            "WARNING",
        )
        flash(message, "error")

    return render_template("register.html", user=g.user)


@app.route("/global-documents")
def global_documents():
    # show all documents marked as global.
    #
    # this route is public and does not require login.
    global_docs = get_global_documents()

    log_access_event(
        f"GLOBAL_DOCS_VIEW ip={request.remote_addr} user={g.user['username'] if g.user else 'anonymous'}"
    )

    return render_template(
        "global_documents.html",
        user=g.user,
        global_docs=global_docs
    )


@app.route("/admin/manage-docs")
@require_login
@require_role("admin")
def admin_manage_docs():
    # show the admin panel for managing global documents.
    #
    # only logged-in admins can access this page.
    global_docs = get_global_documents()

    log_access_event(
        f"ADMIN_MANAGE_DOCS admin={g.user['username']} ip={request.remote_addr}"
    )

    return render_template(
        "admin_manage_docs.html",
        user=g.user,
        global_docs=global_docs
    )


@app.route("/admin/docs/upload", methods=["POST"])
@require_login
@require_role("admin")
def admin_upload_doc():
    # allow an admin to upload a new global document.
    #
    # this route:
    # - reads the uploaded file
    # - validates type and content
    # - creates document metadata
    # - encrypts and stores the file
    uploaded_file = request.files.get("document")

    # reject missing uploads.
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please choose a file.", "error")
        return redirect(url_for("admin_manage_docs"))

    # reject files with disallowed extensions.
    if not allowed_file(uploaded_file.filename):
        flash("Invalid file type.", "error")
        log_security_event(
            f"ADMIN_UPLOAD_FAIL admin={g.user['username']} reason=bad_extension ip={request.remote_addr}",
            "WARNING",
        )
        return redirect(url_for("admin_manage_docs"))

    # read the raw file bytes into memory.
    raw_bytes = uploaded_file.read()

    # reject empty files.
    if not raw_bytes:
        flash("Uploaded file is empty.", "error")
        log_security_event(
            f"ADMIN_UPLOAD_FAIL admin={g.user['username']} reason=empty_file ip={request.remote_addr}",
            "WARNING",
        )
        return redirect(url_for("admin_manage_docs"))

    # reject files whose reported mime type is not allowed for the extension.
    if not allowed_mime_type(uploaded_file.filename, uploaded_file.mimetype):
        flash("Invalid MIME type.", "error")
        log_security_event(
            f"ADMIN_UPLOAD_FAIL admin={g.user['username']} reason=bad_mime mimetype={uploaded_file.mimetype} ip={request.remote_addr}",
            "WARNING",
        )
        return redirect(url_for("admin_manage_docs"))

    # reject files whose actual content does not match the declared type.
    if not file_signature_matches(uploaded_file.filename, raw_bytes):
        flash("File content does not match the declared file type.", "error")
        log_security_event(
            f"ADMIN_UPLOAD_FAIL admin={g.user['username']} reason=bad_signature filename={uploaded_file.filename} ip={request.remote_addr}",
            "WARNING",
        )
        return redirect(url_for("admin_manage_docs"))

    # create the metadata record for the global document.
    doc = create_global_document(
        original_name=uploaded_file.filename,
        admin_user_id=g.user["id"]
    )

    # build the full encrypted storage path and save the encrypted file there.
    save_path = document_storage_path(doc["stored_name"])
    encrypted_storage.save_encrypted_file(save_path, raw_bytes)

    log_access_event(
        f"ADMIN_UPLOAD_GLOBAL_SUCCESS admin={g.user['username']} doc_id={doc['id']} ip={request.remote_addr}"
    )
    flash("Global document uploaded successfully.", "success")
    return redirect(url_for("admin_manage_docs"))


@app.route("/admin/docs/<doc_id>/delete", methods=["POST"])
@require_login
@require_role("admin")
def admin_delete_doc(doc_id):
    # allow an admin to soft delete a global document.
    success = delete_global_document(doc_id, g.user["id"])

    if success:
        log_access_event(
            f"ADMIN_DELETE_GLOBAL_SUCCESS admin={g.user['username']} doc_id={doc_id} ip={request.remote_addr}"
        )
        flash("Global document deleted successfully.", "success")
    else:
        log_security_event(
            f"ADMIN_DELETE_GLOBAL_FAIL admin={g.user['username']} doc_id={doc_id} reason=not_found ip={request.remote_addr}",
            "WARNING",
        )
        flash("Document not found or is not a global document.", "error")

    return redirect(url_for("admin_manage_docs"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # handle login.
    #
    # get requests show the login page.
    # post requests verify credentials and create a session.
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # authenticate the submitted credentials.
        ok, message, user = authenticate_user(username, password, request.remote_addr)

        if not ok:
            # if login fails, record it and show the login page again.
            log_security_event(
                f"LOGIN_FAIL username={username} ip={request.remote_addr} reason={message}",
                "WARNING",
            )
            flash(message, "error")
            return render_template("login.html", user=g.user)

        # if login succeeds, create a session token.
        token = session_manager.create_session(user["id"])

        # prepare a redirect response to the dashboard.
        response = make_response(redirect(url_for("dashboard")))

        # store the session token in a browser cookie.
        # httponly helps protect against javascript access.
        # secure means the cookie should only be sent over https.
        # samesite=strict helps reduce some csrf-style cross-site risks.
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            httponly=True,
            secure=request.is_secure,
            samesite="Strict",
            max_age=1800,
        )

        # log successful login and session creation.
        log_security_event(
            f"LOGIN_SUCCESS username={username} ip={request.remote_addr}",
            "INFO",
        )

        log_security_event(
            f"SESSION_CREATED username={username} user_id={user['id']} ip={request.remote_addr}",
            "INFO",
        )
        return response

    return render_template("login.html", user=g.user)


@app.route("/logout", methods=["POST"])
def logout():
    # handle logout.
    #
    # this destroys the server-side session and removes the cookie from the browser.
    token = request.cookies.get(SESSION_COOKIE_NAME)
    response = make_response(redirect(url_for("index")))

    # keep basic user information for logging, even if the session disappears.
    username = g.user["username"] if g.user else "unknown"
    user_id = g.user["id"] if g.user else "unknown"

    if token:
        session_manager.destroy_session(token)
        log_security_event(
            f"LOGOUT user={username} ip={request.remote_addr}",
            "INFO",
        )
        log_security_event(
            f"SESSION_DESTROYED user={username} user_id={user_id} ip={request.remote_addr}",
            "INFO",
        )

    # instruct the browser to delete the session cookie too.
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.route("/dashboard")
@require_login
def dashboard():
    # show the main user dashboard.
    #
    # admins see all non-deleted documents as owned_docs.
    # normal users see:
    # - their own non-deleted documents
    # - documents that have been shared with them
    documents = load_documents()
    shares = load_shares()

    if can_view_all_content(g.user):
        # admins can view all documents in the system.
        owned_docs = [d for d in documents if not d.get("deleted", False)]
        shared_docs = []
    else:
        # non-admin users only see their own documents here.
        owned_docs = [
            d for d in documents
            if d["owner_id"] == g.user["id"] and not d.get("deleted", False)
        ]

        # build the list of documents shared with the current user.
        shared_docs = []
        for d in documents:
            if d.get("deleted", False):
                continue
            role = shares.get(d["id"], {}).get(g.user["id"])
            if role and d["owner_id"] != g.user["id"]:
                shared_docs.append({"doc": d, "role": role})

    log_access_event(
        f"DASHBOARD_ACCESS user={g.user['username']} role={g.user['role']} ip={request.remote_addr}"
    )

    return render_template(
        "dashboard.html",
        user=g.user,
        owned_docs=owned_docs,
        shared_docs=shared_docs,
    )


@app.route("/admin/users")
@require_login
@require_role("admin")
def admin_users():
    # show the admin page for viewing and managing user accounts.
    users = load_users()
    log_access_event(
        f"ADMIN_VIEW_USERS admin={g.user['username']} ip={request.remote_addr}"
    )
    return render_template("admin_users.html", user=g.user, users=users)


@app.route("/admin/users/update-role", methods=["POST"])
@require_login
@require_role("admin")
def update_user_role():
    # allow an admin to change another user's system role.
    #
    # if a user is changed to guest, editor access on existing shared files
    # is automatically downgraded to viewer access.
    target_user_id = request.form.get("user_id", "").strip()
    new_role = request.form.get("role", "").strip().lower()

    # reject unsupported roles.
    if new_role not in {"admin", "user", "guest"}:
        flash("Invalid role selected.", "error")
        return redirect(url_for("admin_users"))

    users = load_users()
    target_user = next((u for u in users if u["id"] == target_user_id), None)

    # stop if the selected target user does not exist.
    if not target_user:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))

    # record the old role before changing it.
    old_role = target_user.get("role", "user")
    target_user["role"] = new_role
    save_users(users)

    # if the user is being downgraded to guest, downgrade editor access to viewer.
    changed_docs = []
    if new_role == "guest" and old_role != "guest":
        changed_docs = downgrade_guest_permissions(target_user_id, g.user["id"])

    log_security_event(
        f"ADMIN_ROLE_CHANGE admin={g.user['username']} target={target_user['username']} old_role={old_role} new_role={new_role} downgraded_docs={len(changed_docs)} ip={request.remote_addr}",
        "INFO",
    )

    # show a more specific success message if document permissions were changed too.
    if changed_docs:
        flash(
            f"Updated {target_user['username']} to guest and downgraded editor access on {len(changed_docs)} document(s).",
            "success",
        )
    else:
        flash(f"Updated {target_user['username']} to role: {new_role}", "success")

    return redirect(url_for("admin_users"))


@app.route("/upload", methods=["GET", "POST"])
@require_login
def upload():
    # allow a logged-in user with the right role to upload a new document.
    #
    # admins and normal users can upload.
    # guests cannot upload.
    if not can_create_content(g.user):
        log_security_event(
            f"UPLOAD_DENIED user={g.user['username']} role={g.user['role']} ip={request.remote_addr}",
            "WARNING",
        )
        flash("Paws off! You do not have upload permissions.", "error")
        abort(403)

    if request.method == "POST":
        uploaded_file = request.files.get("document")

        # reject if no file was selected.
        if not uploaded_file or uploaded_file.filename == "":
            flash("Please choose a file.", "error")
            return render_template("upload.html", user=g.user)

        # reject based on disallowed extension.
        if not allowed_file(uploaded_file.filename):
            flash("Invalid file type.", "error")
            log_security_event(
                f"UPLOAD_FAIL user={g.user['username']} reason=bad_extension ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("upload.html", user=g.user)

        # read the uploaded file into memory.
        raw_bytes = uploaded_file.read()

        # reject empty files.
        if not raw_bytes:
            flash("Uploaded file is empty.", "error")
            log_security_event(
                f"UPLOAD_FAIL user={g.user['username']} reason=empty_file ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("upload.html", user=g.user)

        # reject files with an invalid mime type for the chosen extension.
        if not allowed_mime_type(uploaded_file.filename, uploaded_file.mimetype):
            flash("Invalid MIME type.", "error")
            log_security_event(
                f"UPLOAD_FAIL user={g.user['username']} reason=bad_mime mimetype={uploaded_file.mimetype} ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("upload.html", user=g.user)

        # reject files whose content signature does not match the expected file type.
        if not file_signature_matches(uploaded_file.filename, raw_bytes):
            flash("File content does not match the declared file type.", "error")
            log_security_event(
                f"UPLOAD_FAIL user={g.user['username']} reason=bad_signature filename={uploaded_file.filename} ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("upload.html", user=g.user)

        # create the document metadata record.
        doc = create_document_record(
            owner_id=g.user["id"],
            original_name=uploaded_file.filename,
        )

        # encrypt the file and save it to the correct storage path.
        save_path = document_storage_path(doc["stored_name"])
        encrypted_storage.save_encrypted_file(save_path, raw_bytes)

        log_access_event(
            f"UPLOAD_SUCCESS user={g.user['username']} doc_id={doc['id']} ip={request.remote_addr}"
        )
        flash("File uploaded successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("upload.html", user=g.user)


@app.route("/download/<doc_id>")
@require_login
def download(doc_id):
    # allow a user to download a document if they have access.
    #
    # the route:
    # - checks that the document exists
    # - checks authorization
    # - loads and decrypts the file
    # - sends it back as a downloadable attachment
    doc = get_document_by_id(doc_id)
    if not doc:
        abort(404)

    # this check is somewhat redundant because require_login already guarantees
    # a logged-in user, but it is kept here as an extra safeguard.
    if not g.user:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    # global documents are intentionally accessible without normal share checks.
    if doc.get("is_global", False):
        pass
    else:
        # for normal documents, require appropriate document permissions.
        if not can_download(doc_id, g.user["id"]):
            log_security_event(
                f"DOWNLOAD_DENIED user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}",
                "WARNING",
            )
            abort(403)

    encrypted_path = document_storage_path(doc["stored_name"])
    if not encrypted_path.exists():
        abort(404)

    # decrypt the file contents in memory before sending them to the user.
    decrypted_bytes = encrypted_storage.load_decrypted_file(encrypted_path)

    log_access_event(
        f"DOWNLOAD_SUCCESS user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}"
    )

    return send_file(
        BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=doc["original_name"],
        mimetype=doc.get("mime_type", "application/octet-stream"),
    )


@app.route("/share/<doc_id>", methods=["GET", "POST"])
@require_login
def share(doc_id):
    # allow the owner of a document to share it with another user.
    doc = get_document_by_id(doc_id)
    if not doc:
        abort(404)

    # only the owner may share a document.
    if not is_owner(doc_id, g.user["id"]):
        log_security_event(
            f"SHARE_DENIED user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}",
            "WARNING",
        )
        abort(403)

    if request.method == "POST":
        target_username = request.form.get("username", "").strip()
        role = request.form.get("role", "").strip()

        # ask the document service to perform the sharing logic.
        ok, message = share_document(doc_id, g.user["id"], target_username, role)

        if ok:
            log_access_event(
                f"SHARE_SUCCESS user={g.user['username']} doc_id={doc_id} target={target_username} role={role} ip={request.remote_addr}"
            )
            flash(message, "success")
            return redirect(url_for("dashboard"))

        log_security_event(
            f"SHARE_FAIL user={g.user['username']} doc_id={doc_id} target={target_username} role={role} ip={request.remote_addr} reason={message}",
            "WARNING",
        )
        flash(message, "error")

    return render_template("share.html", user=g.user, doc=doc)


@app.route("/document/<doc_id>/new-version", methods=["GET", "POST"])
@require_login
def upload_new_version(doc_id):
    # allow an owner or editor to upload a new version of an existing document.
    doc = get_document_by_id(doc_id)
    if not doc:
        abort(404)

    # only users with edit-level access may upload a new version.
    if not can_edit(doc_id, g.user["id"]):
        log_security_event(
            f"NEW_VERSION_DENIED user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}",
            "WARNING",
        )
        abort(403)

    if request.method == "POST":
        uploaded_file = request.files.get("document")

        # reject missing selection.
        if not uploaded_file or uploaded_file.filename == "":
            flash("Please choose a file.", "error")
            return render_template("new_version.html", user=g.user, doc=doc)

        # reject invalid extension.
        if not allowed_file(uploaded_file.filename):
            flash("Invalid file type.", "error")
            log_security_event(
                f"NEW_VERSION_FAIL user={g.user['username']} doc_id={doc_id} reason=bad_extension ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("new_version.html", user=g.user, doc=doc)

        # reject invalid mime type.
        if not allowed_mime_type(uploaded_file.filename, uploaded_file.mimetype):
            flash("Invalid MIME type.", "error")
            log_security_event(
                f"NEW_VERSION_FAIL user={g.user['username']} doc_id={doc_id} reason=bad_mime mimetype={uploaded_file.mimetype} ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("new_version.html", user=g.user, doc=doc)

        # read the new file into memory.
        raw_bytes = uploaded_file.read()

        # reject empty files.
        if not raw_bytes:
            flash("Uploaded file is empty.", "error")
            log_security_event(
                f"NEW_VERSION_FAIL user={g.user['username']} doc_id={doc_id} reason=empty_file ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("new_version.html", user=g.user, doc=doc)

        # reject files whose content does not match their claimed type.
        if not file_signature_matches(uploaded_file.filename, raw_bytes):
            flash("File content does not match the declared file type.", "error")
            log_security_event(
                f"NEW_VERSION_FAIL user={g.user['username']} doc_id={doc_id} reason=bad_signature filename={uploaded_file.filename} ip={request.remote_addr}",
                "WARNING",
            )
            return render_template("new_version.html", user=g.user, doc=doc)

        # update the document metadata to reflect the new version.
        updated_doc = update_document_version(
            doc_id=doc_id,
            user_id=g.user["id"],
            new_original_name=uploaded_file.filename,
        )

        if not updated_doc:
            abort(404)

        # encrypt and store the new file version.
        save_path = document_storage_path(updated_doc["stored_name"])
        encrypted_storage.save_encrypted_file(save_path, raw_bytes)

        log_access_event(
            f"NEW_VERSION_SUCCESS user={g.user['username']} doc_id={doc_id} version={updated_doc['latest_version']} ip={request.remote_addr}"
        )
        flash("New version uploaded successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_version.html", user=g.user, doc=doc)


@app.route("/document/<doc_id>/delete", methods=["POST"])
@require_login
def remove_document(doc_id):
    # allow an owner or admin to soft delete a document.
    doc = get_document_by_id(doc_id)
    if not doc:
        abort(404)

    # check deletion permission before calling the delete helper.
    if not can_delete(doc_id, g.user["id"]):
        log_security_event(
            f"DELETE_DENIED user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}",
            "WARNING",
        )
        abort(403)

    # perform the actual delete operation.
    ok, message = delete_document(doc_id, g.user["id"])

    if ok:
        log_access_event(
            f"DELETE_SUCCESS user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}"
        )
        flash(message, "success")
    else:
        log_security_event(
            f"DELETE_FAIL user={g.user['username']} doc_id={doc_id} ip={request.remote_addr} reason={message}",
            "WARNING",
        )
        flash(message, "error")

    return redirect(url_for("dashboard"))


@app.route("/view/<doc_id>")
@require_login
def view_file(doc_id):
    # allow a user to view a document in the browser if they have access.
    #
    # unlike the download route, this sends the file inline rather than
    # forcing it to download as an attachment.
    doc = get_document_by_id(doc_id)
    if not doc:
        abort(404)

    # global documents bypass normal sharing checks.
    if doc.get("is_global", False):
        pass
    else:
        if not can_download(doc_id, g.user["id"]):
            log_security_event(
                f"VIEW_DENIED user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}",
                "WARNING",
            )
            abort(403)

    encrypted_path = document_storage_path(doc["stored_name"])
    if not encrypted_path.exists():
        abort(404)

    # decrypt the file and send it inline for browser viewing.
    decrypted_bytes = encrypted_storage.load_decrypted_file(encrypted_path)

    log_access_event(
        f"VIEW_SUCCESS user={g.user['username']} doc_id={doc_id} ip={request.remote_addr}"
    )

    return send_file(
        BytesIO(decrypted_bytes),
        as_attachment=False,
        download_name=doc["original_name"],
        mimetype=doc.get("mime_type", "application/octet-stream"),
    )


@app.route("/change-password", methods=["GET", "POST"])
@require_login
def change_password():
    # allow a logged-in user to change their password.
    #
    # the auth module performs the actual verification and update.
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        ok, message = update_user_password(
            g.user["id"],
            current_password,
            new_password,
            confirm_password
        )

        if ok:
            log_security_event(
                f"PASSWORD_CHANGED user={g.user['username']} ip={request.remote_addr}",
                "INFO",
            )
            flash(message, "success")
            return redirect(url_for("dashboard"))

        log_security_event(
            f"PASSWORD_CHANGE_FAILED user={g.user['username']} ip={request.remote_addr} reason={message}",
            "WARNING",
        )
        flash(message, "error")

    return render_template("change_password.html", user=g.user)


@app.errorhandler(403)
def forbidden(error):
    # render a custom 403 page whenever the app raises a forbidden error.
    return render_template("403.html", user=g.user), 403


if __name__ == "__main__":
    # initialize required folders and json files before the app starts.
    initialize_project_files()

    # if tls certificate and key files exist, configure flask to serve over https.
    ssl_context = None
    if CERT_FILE.exists() and TLS_KEY_FILE.exists():
        ssl_context = (str(CERT_FILE), str(TLS_KEY_FILE))

    # start the flask app.
    # debug mode and tls behavior are controlled by values from config.py.
    app.run(debug=DEBUG, ssl_context=ssl_context)