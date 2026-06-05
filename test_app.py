 
"""
Unit tests for CyberShield application.
"""

import pytest
from app import app, hash_data, validate_input


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_hash_data_returns_string():
    result = hash_data("hello")
    assert isinstance(result, str)


def test_hash_data_is_sha256_length():
    result = hash_data("hello")
    assert len(result) == 64


def test_hash_data_deterministic():
    assert hash_data("test") == hash_data("test")


def test_hash_data_different_inputs():
    assert hash_data("abc") != hash_data("xyz")


def test_validate_input_valid():
    assert validate_input("hello world") is True


def test_validate_input_empty():
    assert validate_input("") is False


def test_validate_input_too_long():
    assert validate_input("a" * 300) is False


def test_validate_input_special_chars():
    assert validate_input("hello; DROP TABLE users;") is False


def test_home_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200


def test_ping_endpoint(client):
    response = client.get("/ping")
    assert response.status_code == 200


def test_hash_endpoint_valid(client):
    response = client.post("/hash", json={"data": "mypassword"})
    assert response.status_code == 200


def test_hash_endpoint_missing_field(client):
    response = client.post("/hash", json={})
    assert response.status_code == 400


def test_hash_endpoint_invalid_chars(client):
    response = client.post("/hash", json={"data": "<script>alert(1)</script>"})
    assert response.status_code == 422