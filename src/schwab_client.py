"""
Thin REST wrapper around the Schwab Trader API — LITE edition.

This lite client covers reads only: quotes, price history, and the account
snapshot (balances + positions). It is enough to authenticate and pull market
data, which is the point of the free starter. Order placement, fill polling,
streaming, and everything else live in the full framework (see the README).

Docs: https://developer.schwab.com/products/trader-api--individual
All endpoints are relative to https://api.schwabapi.com.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import pytz
import requests

from .auth import SchwabAuth

log = logging.getLogger(__name__)
_ET = pytz.timezone("America/New_York")

MARKET_BASE = "https://api.schwabapi.com/marketdata/v1"
TRADER_BASE = "https://api.schwabapi.com/trader/v1"

# Keywords in `securityStatus` that indicate the security is halted or paused.
_HALT_KEYWORDS = ("halt", "pause", "suspend", "luld")


def _parse_halted(symbol_data: dict) -> bool:
    """True if Schwab reports the security is halted, paused, or suspended."""
    status = (symbol_data.get("securityStatus") or "").lower()
    return any(k in status for k in _HALT_KEYWORDS)


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Robust float conversion. Returns `default` for None / non-numeric —
    Schwab intermittently returns null prices on halted names, and an
    unprotected float() would crash the whole batch quote call."""
    if val is None:
        return default
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


@dataclass
class Quote:
    symbol: str
    bid: float
    ask: float
    last: float
    volume: int
    prev_close: float
    timestamp: float
    is_halted: bool = False

    @property
    def mid(self) -> float:
        if self.bid > 0 and self.ask > 0:
            return (self.bid + self.ask) / 2.0
        return self.last


class SchwabClient:
    def __init__(self, auth: SchwabAuth, account_hash: Optional[str] = None):
        self.auth = auth
        self._account_hash = account_hash
        # Thread-local requests.Session: requests.Session isn't thread-safe,
        # so each thread gets its own, created lazily on first use.
        self._session_local = threading.local()

    def _session(self) -> requests.Session:
        s = getattr(self._session_local, "s", None)
        if s is None:
            s = requests.Session()
            self._session_local.s = s
        return s

    # -- helpers -----------------------------------------------------------
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.auth.get_valid_access_token()}",
            "Accept": "application/json",
        }

    def _get(self, url: str, **kwargs) -> Any:
        sess = self._session()
        resp = sess.get(url, headers=self._headers(), timeout=15, **kwargs)
        if resp.status_code == 401:
            # Token expired between calls — force one refresh and retry.
            self.auth._refresh()  # noqa: SLF001
            resp = sess.get(url, headers=self._headers(), timeout=15, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    # -- accounts ----------------------------------------------------------
    def list_accounts(self) -> dict[str, str]:
        """Return {accountNumber: hashValue} for every account on this login."""
        data = self._get(f"{TRADER_BASE}/accounts/accountNumbers")
        if not data:
            return {}
        out: dict[str, str] = {}
        for acct in data:
            number = str(acct.get("accountNumber", "")).strip()
            hash_value = str(acct.get("hashValue", "")).strip()
            if number and hash_value:
                out[number] = hash_value
        return out

    def account_hash(self) -> str:
        """Resolve the Schwab account hash to use for balances.

        If SCHWAB_BOT_ACCOUNT_NUMBER is set in .env, look up that account and
        use its hash (the safe path for multi-account logins). If it's unset:
        single-account logins use the only account; multi-account logins
        refuse to guess and raise with the available account numbers.
        """
        if self._account_hash:
            return self._account_hash
        data = self._get(f"{TRADER_BASE}/accounts/accountNumbers")
        if not data:
            raise RuntimeError("No Schwab accounts returned for this login.")

        desired = os.getenv("SCHWAB_BOT_ACCOUNT_NUMBER", "").strip()
        if desired:
            for acct in data:
                if str(acct.get("accountNumber", "")) == desired:
                    self._account_hash = acct["hashValue"]
                    return self._account_hash
            available = [str(a.get("accountNumber", "")) for a in data]
            raise RuntimeError(
                f"SCHWAB_BOT_ACCOUNT_NUMBER={desired} not found. Available: "
                f"{available}. Fix .env, or remove the var if you only have one."
            )

        if len(data) > 1:
            available = [str(a.get("accountNumber", "")) for a in data]
            raise RuntimeError(
                f"Multiple Schwab accounts found ({available}) but "
                f"SCHWAB_BOT_ACCOUNT_NUMBER is not set in .env. Pick one "
                f"explicitly so the client doesn't guess."
            )

        self._account_hash = data[0]["hashValue"]
        return self._account_hash

    def account(self, account_hash: Optional[str] = None) -> dict:
        """Snapshot of the account (balances, positions, projected balances)."""
        acct = account_hash or self.account_hash()
        return self._get(f"{TRADER_BASE}/accounts/{acct}")

    def positions(self, account_hash: Optional[str] = None) -> list[dict]:
        """Open positions on the account."""
        acc = self.account(account_hash=account_hash)
        return acc.get("securitiesAccount", {}).get("positions", []) or []

    # -- market data -------------------------------------------------------
    def quote(self, symbol: str) -> Quote:
        data = self._get(f"{MARKET_BASE}/{symbol}/quotes")
        sym_data = data.get(symbol, {})
        q = sym_data.get("quote", {})
        return Quote(
            symbol=symbol,
            bid=_safe_float(q.get("bidPrice")),
            ask=_safe_float(q.get("askPrice")),
            last=_safe_float(q.get("lastPrice")),
            volume=_safe_int(q.get("totalVolume")),
            prev_close=_safe_float(q.get("closePrice")),
            timestamp=time.time(),
            is_halted=_parse_halted(sym_data),
        )

    def quotes(self, symbols: Iterable[str]) -> dict[str, Quote]:
        syms = ",".join(symbols)
        data = self._get(f"{MARKET_BASE}/quotes", params={"symbols": syms})
        out: dict[str, Quote] = {}
        for sym, entry in data.items():
            sym_data = entry if isinstance(entry, dict) else {}
            q = sym_data.get("quote", {}) if isinstance(sym_data, dict) else {}
            out[sym] = Quote(
                symbol=sym,
                bid=_safe_float(q.get("bidPrice")),
                ask=_safe_float(q.get("askPrice")),
                last=_safe_float(q.get("lastPrice")),
                volume=_safe_int(q.get("totalVolume")),
                prev_close=_safe_float(q.get("closePrice")),
                timestamp=time.time(),
                is_halted=_parse_halted(sym_data),
            )
        return out

    def price_history(
        self,
        symbol: str,
        period_type: str = "day",
        period: int = 1,
        frequency_type: str = "minute",
        frequency: int = 1,
        need_extended_hours: bool = True,
        start_date_ms: Optional[int] = None,
        end_date_ms: Optional[int] = None,
    ) -> list[dict]:
        """Return a list of OHLCV candles: {datetime, open, high, low, close,
        volume}. For period_type="day" we translate to an explicit ET
        start/end window so today's intraday bars are always included
        (Schwab's day shortcut sometimes returns only completed sessions)."""
        params: dict = {
            "symbol": symbol,
            "frequencyType": frequency_type,
            "frequency": frequency,
            "needExtendedHoursData": str(need_extended_hours).lower(),
        }
        if start_date_ms is not None and end_date_ms is not None:
            params["startDate"] = start_date_ms
            params["endDate"] = end_date_ms
        elif period_type == "day":
            now = dt.datetime.now(_ET)
            start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
            start_day = start_of_today - dt.timedelta(days=max(0, period - 1))
            params["startDate"] = int(start_day.timestamp() * 1000)
            params["endDate"] = int(now.timestamp() * 1000)
        else:
            params["periodType"] = period_type
            params["period"] = period
        data = self._get(f"{MARKET_BASE}/pricehistory", params=params)
        return data.get("candles", []) or []
