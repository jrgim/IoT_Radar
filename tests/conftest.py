import pytest
import database


@pytest.fixture
def tmp_db(tmp_path):
    db_file = str(tmp_path / "test.db")
    database.init_db(db_file)
    yield db_file


@pytest.fixture
def alert_calls(monkeypatch):
    calls = []

    def _fake(severity, category, title, detail, recommendation=""):
        calls.append({"severity": severity, "category": category, "title": title})
        return True

    monkeypatch.setattr("alert_engine.create_alert", _fake)
    return calls
