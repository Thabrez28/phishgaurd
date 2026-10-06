"""
Pytest fixtures and environment configuration.
"""
import pytest
from app import create_app
from models import db, User

@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def test_user(app):
    with app.app_context():
        user = User(username="analyst1", email="analyst1@phishguard.test", role="user")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def test_admin(app):
    with app.app_context():
        admin = User(username="admin_soc", email="admin_soc@phishguard.test", role="admin")
        admin.set_password("AdminSecurePass123!")
        db.session.add(admin)
        db.session.commit()
        return admin
