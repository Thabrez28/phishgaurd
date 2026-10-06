"""
Authentication, Password Hashing, and Access Control Tests.
"""
from models import User

def test_password_hashing():
    """Verify password is encrypted using strong one-way hash."""
    user = User(username="test_hasher", email="hasher@test.com")
    user.set_password("MySecretPass!2026")
    
    assert user.password_hash != "MySecretPass!2026"
    assert user.check_password("MySecretPass!2026") is True
    assert user.check_password("WrongPassword") is False

def test_user_registration(client, app):
    """Test user registration workflow."""
    res = client.post("/register", data={
        "username": "new_operative",
        "email": "operative@phishguard.test",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)

    assert res.status_code == 200
    with app.app_context():
        u = User.query.filter_by(username="new_operative").first()
        assert u is not None
        assert u.email == "operative@phishguard.test"

def test_registration_mismatched_password(client):
    """Verify registration fails if passwords do not match."""
    res = client.post("/register", data={
        "username": "mismatch_user",
        "email": "mismatch@test.com",
        "password": "Password123!",
        "confirm_password": "DifferentPass456!"
    })
    assert b"Password confirmation does not match" in res.data

def test_login_and_logout(client, test_user):
    """Verify successful login and session termination."""
    # Login
    res = client.post("/login", data={
        "username": "analyst1",
        "password": "SecurePass123!"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Welcome back, Operator analyst1" in res.data

    # Logout
    logout_res = client.get("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"Session terminated securely" in logout_res.data

def test_failed_login_and_lockout(client, app, test_user):
    """Verify account locks after 5 consecutive failed attempts."""
    for i in range(5):
        client.post("/login", data={
            "username": "analyst1",
            "password": "WrongPassword"
        })

    with app.app_context():
        u = User.query.filter_by(username="analyst1").first()
        assert u.is_locked is True

    # 6th attempt should inform about lockout
    lockout_res = client.post("/login", data={
        "username": "analyst1",
        "password": "SecurePass123!"
    }, follow_redirects=True)
    assert b"Account is locked due to excessive failed attempts" in lockout_res.data

def test_admin_route_protection(client, test_user):
    """Regular users must be blocked (403) from admin panel."""
    # Login as regular user
    client.post("/login", data={
        "username": "analyst1",
        "password": "SecurePass123!"
    })

    res = client.get("/admin/")
    assert res.status_code == 403
    assert b"403 FORBIDDEN" in res.data
