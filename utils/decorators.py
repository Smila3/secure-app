# this module contains decorators and helper functions related to authorization.
# these functions are used to protect routes and to answer questions like:
# - is the user logged in?
# - is the user an admin?
# - is the user allowed to create content?
# - can the user manage other users?
# - can the user view all content in the system?

from functools import wraps
from flask import g, flash, redirect, url_for, abort


def require_login(view_func):
    # this decorator protects a route so that only logged-in users can access it.
    #
    # if there is no authenticated user stored in flask's global "g" object,
    # the function flashes an error message and redirects the visitor to the login page.
    #
    # if a user is logged in, the original route function runs normally.

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        # g.user is set during request processing in app.py.
        # if it is missing or none, the request is not authenticated.
        if not g.user:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        # if the user is logged in, continue to the original route.
        return view_func(*args, **kwargs)

    return wrapper


def require_role(*allowed_roles):
    # this decorator protects a route so that only users with certain roles can access it.
    #
    # allowed_roles is a variable-length argument list, which means the decorator can accept
    # one or more roles such as:
    # - @require_role("admin")
    # - @require_role("admin", "user")
    #
    # if the current user is not logged in or does not have one of the allowed roles,
    # the request is stopped with a 403 forbidden error.

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # deny access if there is no logged-in user
            # or if the user's role is not in the allowed set.
            if not g.user or g.user.get("role") not in allowed_roles:
                abort(403)

            # if the role is allowed, continue to the original route.
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def is_admin(user):
    # return true only if the given user exists and has the admin role.
    # this is a convenience helper used when checking admin-only behavior.
    return user and user.get("role") == "admin"


def can_create_content(user):
    # return true if the user is allowed to create content such as uploads.
    #
    # in this system:
    # - admins can create content
    # - standard users can create content
    # - guests cannot create content
    return user and user.get("role") in {"admin", "user"}


def can_manage_users(user):
    # return true only if the user is an admin.
    # only admins are allowed to manage other user accounts and role assignments.
    return user and user.get("role") == "admin"


def can_view_all_content(user):
    # return true only if the user is an admin.
    #
    # this helper is used for cases where admins are allowed to see all documents
    # in the system, while regular users can only see their own or shared content.
    return user and user.get("role") == "admin"