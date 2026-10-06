"""
Authentication and Identity Management Routes.
Handles registration, login, logout, failed attempt detection, and role-based access control.
"""
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from models import db, User
from security.security_logger import log_security_event, trigger_security_alert, get_client_ip, get_client_user_agent

auth_bp = Blueprint("auth", __name__)

def login_required(f):
    """Restricts access to authenticated users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Authentication required. Please log in to access this resource.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Restricts access exclusively to administrators."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Administrative authorization required. Please log in as an administrator.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if session.get("role") != "admin":
            log_security_event(
                event_type="ACCESS_DENIED",
                description=f"User '{session.get('username')}' attempted unauthorized administrative access to '{request.path}'",
                user_id=session.get("user_id")
            )
            flash("Access Denied: Administrative privileges required.", "danger")
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation
        if not username or not email or not password:
            flash("All fields are mandatory.", "danger")
            return render_template("register.html", username=username, email=email)

        if len(username) < 3 or len(username) > 32:
            flash("Username must be between 3 and 32 characters.", "danger")
            return render_template("register.html", username=username, email=email)

        if len(password) < 8:
            flash("Password must be at least 8 characters long with numbers and letters.", "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Password confirmation does not match.", "danger")
            return render_template("register.html", username=username, email=email)

        # Check existing user
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("A user with this username or email already exists.", "danger")
            return render_template("register.html", username=username, email=email)

        # Determine role (First registered user or matching admin email becomes admin)
        is_first_user = User.query.count() == 0
        role = "admin" if is_first_user or email == current_app.config.get("ADMIN_EMAIL") else "user"

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log_security_event(
            event_type="USER_REGISTERED",
            description=f"New user registered: '{username}' with role '{role}'",
            user_id=new_user.id
        )

        flash(f"Account successfully created! You are registered as '{role}'. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username_or_email or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("login.html", username=username_or_email)

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email.lower())
        ).first()

        # Check account lockout
        if user and user.is_locked:
            log_security_event(
                event_type="LOCKED_ACCOUNT_LOGIN_ATTEMPT",
                description=f"Login attempt on locked account '{user.username}'",
                user_id=user.id
            )
            flash("Account is locked due to excessive failed attempts. Please contact security admin.", "danger")
            return render_template("login.html", username=username_or_email)

        if user and user.check_password(password):
            # Login successful
            user.record_login_success()
            db.session.commit()

            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role

            log_security_event(
                event_type="LOGIN_SUCCESS",
                description=f"User '{user.username}' successfully authenticated [{user.role}]",
                user_id=user.id
            )

            flash(f"Welcome back, Operator {user.username}!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard.dashboard"))
        else:
            # Login failed
            if user:
                user.record_login_failure()
                db.session.commit()

                log_security_event(
                    event_type="LOGIN_FAILURE",
                    description=f"Failed password attempt for user '{user.username}' (attempt #{user.failed_login_attempts})",
                    user_id=user.id
                )

                if user.is_locked:
                    trigger_security_alert(
                        alert_type="MULTIPLE FAILED LOGIN ATTEMPTS",
                        severity="HIGH",
                        message=f"Account '{user.username}' automatically locked after 5 consecutive failed login attempts."
                    )
            else:
                log_security_event(
                    event_type="LOGIN_FAILURE",
                    description=f"Failed login attempt for non-existent identifier: '{username_or_email}'"
                )

            flash("Invalid credentials. Please verify your username and password.", "danger")
            return render_template("login.html", username=username_or_email)

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    username = session.get("username", "Unknown")
    user_id = session.get("user_id")

    if user_id:
        log_security_event(
            event_type="LOGOUT",
            description=f"User '{username}' signed out of session",
            user_id=user_id
        )

    session.clear()
    flash("Session terminated securely.", "info")
    return redirect(url_for("auth.login"))
