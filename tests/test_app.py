def register_and_login(client, username="tester", password="secret123"):
    client.post("/register", data={"username": username, "password": password,
                                   "confirm_password": password})
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=True)


def test_scanner_requires_login(client):
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_register_login_logout(client):
    r = register_and_login(client)
    assert b"Phishing URL Scanner" in r.data
    r = client.get("/logout", follow_redirects=True)
    assert b"logged out" in r.data


def test_wrong_password(client):
    register_and_login(client)
    client.get("/logout")
    r = client.post("/login", data={"username": "tester", "password": "wrong"}, follow_redirects=True)
    assert b"Invalid username or password" in r.data


def test_duplicate_username(client):
    register_and_login(client)
    client.get("/logout")
    r = client.post("/register", data={"username": "tester", "password": "secret123",
                                       "confirm_password": "secret123"}, follow_redirects=True)
    assert b"already taken" in r.data


def test_scan_safe_and_dangerous(client):
    register_and_login(client)
    r = client.post("/", data={"url": "https://www.github.com/"})
    assert r.status_code == 200 and b"SAFE" in r.data

    r = client.post("/", data={"url": "http://123.45.67.89/login"})
    assert b"DANGER" in r.data and b"Numeric IP address" in r.data

    r = client.get("/history")
    assert b"github.com" in r.data and b"123.45.67.89" in r.data


def test_invalid_url(client):
    register_and_login(client)
    r = client.post("/", data={"url": "not a url"})
    assert b"valid web address" in r.data
    r = client.post("/", data={"url": ""})
    assert b"Please enter a URL" in r.data


def test_history_is_private(client):
    register_and_login(client, "alice")
    client.post("/", data={"url": "https://www.python.org/"})
    client.get("/logout")
    register_and_login(client, "bob")
    r = client.get("/history")
    assert b"python.org" not in r.data
