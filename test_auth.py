from auth import authenticate_user

def test_missing_credentials():
    db = {}
    assert authenticate_user("", "pass", db) == "Missing credentials"
    assert authenticate_user("user", "", db) == "Missing credentials"

def test_user_not_found():
    db = {}
    assert authenticate_user("user", "pass", db) == "User not found"

def test_account_locked():
    db = {"user": {"password": "pass", "attempts": 3}}
    assert authenticate_user("user", "pass", db) == "Account locked"

def test_invalid_password():
    db = {"user": {"password": "pass", "attempts": 0}}
    assert authenticate_user("user", "wrong", db) == "Invalid password"
    assert db["user"]["attempts"] == 1

def test_success():
    db = {"user": {"password": "pass", "attempts": 1}}
    assert authenticate_user("user", "pass", db) == "Authenticated"
    assert db["user"]["attempts"] == 0

def test_condition_combination_missing_credentials():
    db = {}

    # (False, False) — обидва є → не повинно спрацьовувати
    assert authenticate_user("user", "pass", db) == "User not found"

    # (False, True)
    assert authenticate_user("user", "", db) == "Missing credentials"

    # (True, False)
    assert authenticate_user("", "pass", db) == "Missing credentials"

    # (True, True)
    assert authenticate_user("", "", db) == "Missing credentials"

def test_multiple_wrong_attempts_then_lock():
    db = {"user": {"password": "pass", "attempts": 1}}
    assert authenticate_user("user", "wrong1", db) == "Invalid password"
    assert db["user"]["attempts"] == 2
    assert authenticate_user("user", "wrong2", db) == "Invalid password"
    assert db["user"]["attempts"] == 3
    assert authenticate_user("user", "pass", db) == "Account locked"

def test_mcdc_username_required():
    db = {}
    assert authenticate_user("", "pass", db) == "Missing credentials"  # username → впливає

def test_mcdc_password_required():
    db = {}
    assert authenticate_user("user", "", db) == "Missing credentials"  # password → впливає

def test_mcdc_user_found():
    db = {}
    assert authenticate_user("user", "pass", db) == "User not found"  # username в db → впливає

def test_mcdc_attempts_limit():
    db = {"user": {"password": "pass", "attempts": 3}}
    assert authenticate_user("user", "pass", db) == "Account locked"  # attempts → впливає

def test_attempts_incremented_and_reset():
    db = {"user": {"password": "pass", "attempts": 2}}

    # Неправильний пароль — лічильник зростає
    assert authenticate_user("user", "wrong", db) == "Invalid password"
    assert db["user"]["attempts"] == 3

    # Далі — вже заблоковано
    assert authenticate_user("user", "pass", db) == "Account locked"

    # Заново розблокований користувач
    db["user"]["attempts"] = 1
    assert authenticate_user("user", "pass", db) == "Authenticated"
    assert db["user"]["attempts"] == 0
