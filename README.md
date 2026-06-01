# Schwab API Python Starter (Lite)

Build your own trading bot on the **Schwab API**. This is the free starter: a working login (OAuth) in Python, plus a small client for pulling quotes and account data. The login is the part everyone gets stuck on, and this gets you past it.

This is the **lite version** of the framework from [Build Your Own Schwab Trading Bot with Claude Code](https://stonkmom.gumroad.com/l/schwab-trading-bot). It includes the hardest part to get right (OAuth) plus enough of a REST client to fetch quotes and account info. The full framework adds order placement, risk management, the dashboard, the watchdog layer, the Claude Code workflow guide, and a senior-engineer code-reviewer slash command named Sheldon.

## What's in this repo (free)

- `src/auth.py`, OAuth 2.0 flow against Schwab, self-signed localhost callback, automatic token refresh
- `src/schwab_client.py`, REST wrapper for the Schwab Trader API (quotes and account snapshot only)
- `.env.example`, credentials template
- `requirements.txt`, Python dependencies

That's enough to authenticate and pull market data. Not enough to actually trade.

## You'll need a Schwab account

All of this runs against the Schwab Developer API, which requires a Schwab brokerage account. If you don't have one, you can open one with my referral link: [open a Schwab account](https://www.schwab.com/client-referral?refrid=REFERZQWTDB9M). It's a referral link, so I may get a small bonus. You don't have to use it.

## What's in the paid version

- Order placement (paper-mode simulation + live bracket orders)
- WebSocket streaming for real-time quotes
- Risk layer (position sizing, daily loss caps, max positions)
- Health monitoring + dead-man's-switch
- Phone-accessible dashboard
- Telegram alerts
- The Strategy protocol + a worked example strategy
- 9-chapter playbook covering everything from setup to launch and what comes after, plus a resources appendix and a glossary
- The Sheldon slash command (a senior-engineer code-reviewer)

The playbook and framework are at [stonkmom.gumroad.com](https://stonkmom.gumroad.com/l/schwab-trading-bot).

## Quick start

```bash
git clone https://github.com/stonkmom/schwab-api-starter
cd schwab-api-starter
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate   # Mac/Linux
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your Schwab App Key and App Secret from developer.schwab.com

python -m src.auth
# A browser opens. Log into Schwab. Click through the "your connection
# isn't private" warning (the self-signed cert is the bot's own, not
# actually unsafe). Tokens save to tokens.json.

python -c "from src.auth import SchwabAuth; from src.schwab_client import SchwabClient; print(SchwabClient(SchwabAuth.from_env()).quote('AAPL'))"
# Should print AAPL's current quote.
```

## Who this is for

Python developers who want a working OAuth example for the Schwab Developer API without having to wrangle the localhost callback dance themselves. Getting that flow right from scratch is fiddly and easy to get subtly wrong; here it already works.

If you want to build a full trading bot, the paid version saves you a week of headaches and cursing at your computer.

## License

MIT. Use it however you want. No warranty.

## Disclaimer

Day trading loses money for most people who try it. Algo trading does not change that. This product is not financial advice and the author is not a registered advisor. Use at your own risk and only with money you can afford to lose.

The Schwab API Starter repo is provided to you "as is," without warranty of any kind, either express or implied. StonkMom expressly disclaims any and all representations, warranties or conditions, whether express, implied, or statutory, including without limitation, any implied warranties of merchantability, fitness for a particular purpose, or non-infringement.
