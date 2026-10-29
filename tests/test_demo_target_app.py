import httpx
import pytest
import pytest_asyncio

from demo_target_app import app as demo

TOKEN = "test-token"
AUTH = {"X-Sentinel-Token": TOKEN}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", TOKEN)
    demo.PATCHED = False
    yield
    demo.PATCHED = False


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=demo.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://demo") as c:
        yield c


async def test_health_is_ok_even_when_broken(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "patched": False}


async def test_checkout_fails_initially_with_error_headers(client):
    r = await client.get("/api/checkout")
    assert r.status_code == 500
    assert r.json() == {"error": "KeyError", "detail": "'discount_rate'"}
    assert r.headers["X-Error-File"] == "app.py"
    line = int(r.headers["X-Error-Line"])
    src = open(demo.__file__, encoding="utf-8").read().splitlines()
    assert 'PRICING["discount_rate"]' in src[line - 1]


async def test_hotfix_makes_checkout_succeed_deterministically(client):
    assert (await client.get("/api/checkout")).status_code == 500
    r = await client.post("/admin/apply-hotfix", headers=AUTH)
    assert r.status_code == 200 and r.json() == {"patched": True}
    for _ in range(3):
        ok = await client.get("/api/checkout", params={"sku": "SKU-1", "quantity": 2})
        assert ok.status_code == 200
        assert ok.json() == {
            "status": "ok", "sku": "SKU-1", "quantity": 2,
            "subtotal": 40.0, "discount_rate": 0.0, "total": 43.2,
        }


async def test_simulate_fault_restores_failure(client):
    await client.post("/admin/apply-hotfix", headers=AUTH)
    assert (await client.get("/api/checkout")).status_code == 200
    r = await client.post("/admin/simulate-fault", headers=AUTH)
    assert r.json() == {"patched": False}
    assert (await client.get("/api/checkout")).status_code == 500


@pytest.mark.parametrize("path", ["/admin/apply-hotfix", "/admin/simulate-fault"])
@pytest.mark.parametrize("headers", [{}, {"X-Sentinel-Token": "wrong"}])
async def test_admin_requires_token(client, path, headers):
    assert (await client.post(path, headers=headers)).status_code == 401
    assert demo.PATCHED is False


async def test_admin_rejects_when_token_unconfigured(client, monkeypatch):
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", "")
    r = await client.post("/admin/apply-hotfix", headers={"X-Sentinel-Token": ""})
    assert r.status_code == 401


async def test_unknown_sku_is_404_not_500(client):
    demo.PATCHED = True
    assert (await client.get("/api/checkout", params={"sku": "NOPE"})).status_code == 404


async def test_invalid_quantity_is_422(client):
    assert (await client.get("/api/checkout", params={"quantity": "abc"})).status_code == 422
