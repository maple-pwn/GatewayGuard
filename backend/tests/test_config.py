from app.config import CONFIG_DIR, _resolve_sqlite_url


def test_resolve_relative_aiosqlite_url_against_config_dir():
    resolved = _resolve_sqlite_url("sqlite+aiosqlite:///./gateway_guard.db")
    expected = f"sqlite+aiosqlite:///{(CONFIG_DIR / 'gateway_guard.db').resolve()}"
    assert resolved == expected


def test_keep_absolute_sqlite_url_unchanged():
    url = "sqlite+aiosqlite:////tmp/gateway_guard.db"
    assert _resolve_sqlite_url(url) == url


def test_keep_non_sqlite_url_unchanged():
    url = "postgresql+asyncpg://user:pass@localhost:5432/gateway_guard"
    assert _resolve_sqlite_url(url) == url
