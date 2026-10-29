"""Deliberately broken demo target for Sentinel.

The bugs below (KeyError, unsafe yaml.load, fake hardcoded key, f-string SQL) are
DEMO CONTENT that Sentinel is supposed to find. Do not "fix" them by hand.
"""
import hmac
import os
import sqlite3  
import traceback
from typing import List, Optional 

import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel  

STRIPE_SECRET_KEY = "sk_test_51SENTINELDEMOxxxxxxxx"  # obviously fake demo key  

PATCHED = os.getenv("DEMO_PATCHED", "false").lower() == "true"

PRICING_YAML = "currency: USD\ntax_rate: 0.08\n"  # note: no discount_rate

app = FastAPI(title="Sentinel Demo Target")

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE products (sku TEXT PRIMARY KEY, name TEXT, price REAL)")
db.executemany(
    "INSERT INTO products VALUES (?, ?, ?)",
    [("SKU-1", "Widget", 20.0), ("SKU-2", "Gadget", 35.5)],
)
PRICING = yaml.load(PRICING_YAML, Loader=yaml.Loader)


class CheckoutResponse(BaseModel):
    status: str
    sku: str
    quantity: int
    subtotal: float
    discount_rate: float
    total: float


class AdminResponse(BaseModel):
    patched: bool


class HealthResponse(BaseModel):
    status: str
    patched: bool


class ErrorResponse(BaseModel):
    error: str
    detail: str


def _require_token(token: Optional[str]) -> None:
    expected = os.getenv("DEMO_ADMIN_TOKEN", "")
    if not expected or not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-Sentinel-Token")


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    frames = traceback.extract_tb(exc.__traceback__)
    own = [f for f in frames if os.path.basename(f.filename) == "app.py"]
    line = own[-1].lineno if own else 0
    body = ErrorResponse(error=type(exc).__name__, detail=str(exc))
    return JSONResponse(
        status_code=500,
        content=body.model_dump(),
        headers={"X-Error-File": "app.py", "X-Error-Line": str(line)},
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", patched=PATCHED)


@app.get("/api/checkout", response_model=CheckoutResponse, responses={500: {"model": ErrorResponse}})
async def checkout(sku: str = "SKU-1", quantity: int = 1) -> CheckoutResponse:
    row = db.execute(f"SELECT price FROM products WHERE sku = '{sku}'").fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown sku {sku}")
    subtotal = row[0] * quantity
    if PATCHED:
        discount_rate = PRICING.get("discount_rate", 0.0)
    else:
        discount_rate = PRICING["discount_rate"]
    total = round(subtotal * (1 - discount_rate) * (1 + PRICING["tax_rate"]), 2)
    return CheckoutResponse(
        status="ok", sku=sku, quantity=quantity, subtotal=subtotal,
        discount_rate=discount_rate, total=total,
    )


@app.post("/admin/simulate-fault", response_model=AdminResponse)
async def simulate_fault(x_sentinel_token: Optional[str] = Header(default=None)) -> AdminResponse:
    global PATCHED
    _require_token(x_sentinel_token)
    PATCHED = False
    return AdminResponse(patched=PATCHED)


@app.post("/admin/apply-hotfix", response_model=AdminResponse)
async def apply_hotfix(x_sentinel_token: Optional[str] = Header(default=None)) -> AdminResponse:
    global PATCHED
    _require_token(x_sentinel_token)
    PATCHED = True
    return AdminResponse(patched=PATCHED)


@app.get("/", include_in_schema=False)
async def index() -> dict:
    return {"service": "sentinel-target", "endpoints": ["/health", "/api/checkout"], "patched": PATCHED}


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=204)
