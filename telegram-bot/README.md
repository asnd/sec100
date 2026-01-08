# 3GPP Network Query Telegram Bot

A Telegram bot for querying 3GPP public domain infrastructure worldwide. Discover and analyze mobile network operators, resolve ePDG/IMS/BSF FQDNs to IP addresses in real-time, and explore global telecom infrastructure.

## Features

- 🌍 **Country Search** - Find operators by country name (fuzzy matching)
- 📡 **MCC/MNC Lookup** - Query by Mobile Country/Network Codes
- 📱 **MSISDN Parsing** - Extract operator info from phone numbers
- 🔍 **Operator Search** - Find specific operators with fuzzy matching
- ⚡ **Real-time IP Resolution** - Concurrent DNS resolution of 3GPP FQDNs
- ⏱️ **Rate Limiting** - Prevents abuse (10 queries/min, 50/hour per user)
- 📊 **Query Logging** - Track usage and analytics

## Architecture

```
telegram-bot/
├── main.py                      # Bot entry point
├── config.py                    # Configuration management
├── requirements.txt             # Python dependencies
├── .env.example                 # Configuration template
│
├── handlers/                    # Telegram command handlers
│   ├── help.py                 # /start, /help commands
│   ├── country.py              # /country command
│   ├── mcc_mnc.py              # /mcc, /mnc commands
│   ├── msisdn.py               # /phone command
│   └── operator.py             # /operator command
│
├── services/                    # Business logic
│   ├── database.py             # Async database queries
│   ├── ip_resolver.py          # DNS resolution (concurrent)
│   ├── msisdn_parser.py        # Phone number parsing
│   ├── formatter.py            # Telegram message formatting
│   └── rate_limiter.py         # Per-user rate limiting
│
├── migrations/                  # Database migrations
│   ├── 001_add_countries.py    # Add countries & phone_codes tables
│   └── migrate.py              # Migration runner
│
└── utils/                       # Utilities
    └── logger.py               # Logging configuration
```

## Prerequisites

1. **Python 3.8+**
2. **Telegram Bot Token** - Get from [@BotFather](https://t.me/BotFather)
3. **Populated Database** - Run the 3GPP scanner to populate `database.db`

## Installation

### 1. Clone the Repository

```bash
cd /path/to/sec100
```

### 2. Set Up Virtual Environment

```bash
cd telegram-bot
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Database Migration

The migration adds `countries`, `phone_country_codes`, and `query_log` tables:

```bash
cd migrations
python3 001_add_countries.py
# Or use the migration runner:
python3 migrate.py
```

**Expected output:**
```
Migration completed successfully!
Statistics:
  - Countries table: 255 entries
  - Phone country codes table: 182 entries
  - Unique countries: 231
```

### 5. Configure the Bot

Copy the example configuration and edit it:

```bash
cp .env.example .env
nano .env  # Or use your preferred editor
```

**Required settings:**
```bash
TELEGRAM_BOT_TOKEN=your_bot_token_here
ADMIN_USER_IDS=your_telegram_user_id
DB_PATH=../go-3gpp-scanner/bin/database.db
```

**Get your Telegram user ID:**
- Message [@userinfobot](https://t.me/userinfobot) on Telegram

### 6. Run the Bot

```bash
python3 main.py
```

**Expected output:**
```
============================================================
3GPP Telegram Bot - Configuration
============================================================
Bot Token: ✓ Set
Admin Users: 1
Database: ../go-3gpp-scanner/bin/database.db
Rate Limits: 10/min, 50/hour
DNS Workers: 10 (timeout: 5s)
Pagination: 5 ops/page, 10 FQDNs/op
Log Level: INFO
============================================================
INFO - Initializing services...
INFO - Creating bot application...
INFO - Registering command handlers...
INFO - Starting bot...
INFO - Bot is now running. Press Ctrl+C to stop.
```

## Bot Commands

### Basic Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message and quick start guide |
| `/help` | Command reference and usage examples |

### Query Commands

#### 1. Country Search

Search for operators by country name:

```
/country Austria
```

**Features:**
- Fuzzy matching (partial names work)
- Shows all operators with active infrastructure
- Real-time IP resolution

**Example response:**
```
🌍 Country: Austria (AT)
📡 MCC: 232

Found 3 operators:

1️⃣ A1 Telekom Austria
   • MNC: 1, 91 | MCC: 232
   • Active FQDNs: 4/12

   📍 epdg.epc.mnc001.mcc232.pub.3gppnetwork.org
      → 195.202.128.10, 195.202.128.11
   📍 ims.mnc001.mcc232.pub.3gppnetwork.org
      → 195.202.130.5
```

#### 2. MCC Lookup

Query by Mobile Country Code:

```
/mcc 232
```

Returns all operators for that MCC.

#### 3. MNC Lookup

Query by specific MNC-MCC pair:

```
/mnc 1 232
```

Returns the operator(s) for that specific network code.

#### 4. Phone Number Parsing

Parse international phone numbers:

```
/phone +43-660-1234567
/phone +1-555-1234567
```

**Features:**
- Validates phone number format
- Extracts country code
- Maps to MCC codes
- Shows operators for that country
- Handles multi-country phone codes (+1, +7, etc.)

**Example response:**
```
📱 MSISDN Analysis

Phone: +43 660 1234567
Country: Austria (AT)
MCC: 232

🔍 Found 3 operator(s):
[... operator details ...]
```

#### 5. Operator Search

Search by operator name:

```
/operator Vodafone
/operator T-Mobile
```

**Features:**
- Fuzzy matching (finds partial matches)
- "Did you mean..." suggestions
- Shows all FQDNs and infrastructure

## Configuration Reference

### Environment Variables

All settings are configured via `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | *Required* | Bot token from @BotFather |
| `ADMIN_USER_IDS` | `""` | Comma-separated admin user IDs |
| `DB_PATH` | `../go-3gpp-scanner/bin/database.db` | Path to SQLite database |
| `MAX_QUERIES_PER_MINUTE` | `10` | Rate limit per user per minute |
| `MAX_QUERIES_PER_HOUR` | `50` | Rate limit per user per hour |
| `DNS_RESOLUTION_TIMEOUT` | `5` | DNS timeout in seconds |
| `DNS_CONCURRENT_WORKERS` | `10` | Concurrent DNS resolution workers |
| `MAX_OPERATORS_PER_PAGE` | `5` | Operators shown per page |
| `MAX_FQDNS_PER_OPERATOR` | `10` | FQDNs shown per operator |
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `LOG_FILE` | `bot.log` | Log file path |

### Rate Limiting

**Default limits per user:**
- 10 queries per minute
- 50 queries per hour

**Admin users (set in `ADMIN_USER_IDS`) bypass rate limits.**

When rate limit is exceeded:
```
⏱️ Rate limit: 10 queries/minute exceeded.
Please wait 45 seconds.

Your usage: 10 queries in last minute, 23 queries in last hour.
```

## Database Schema

The bot requires these tables:

### New Tables (created by migration)

**countries** - Maps countries to MCCs
```sql
CREATE TABLE countries (
    country_name TEXT NOT NULL,
    country_code TEXT NOT NULL,  -- ISO 3166-1 alpha-2
    mcc TEXT NOT NULL
);
```

**phone_country_codes** - Maps E.164 phone codes to countries
```sql
CREATE TABLE phone_country_codes (
    phone_code TEXT NOT NULL,     -- E.164 code (e.g., "43", "1")
    country_code TEXT NOT NULL,   -- ISO code (e.g., "AT", "US")
    country_name TEXT NOT NULL
);
```

**query_log** - Tracks bot usage
```sql
CREATE TABLE query_log (
    telegram_user_id INTEGER NOT NULL,
    query_type TEXT NOT NULL,
    query_value TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    result_count INTEGER
);
```

### Existing Tables (from 3GPP scanner)

**operators** - Operator MNC/MCC data
```sql
CREATE TABLE operators (
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT
);
```

**available_fqdns** - Discovered 3GPP FQDNs
```sql
CREATE TABLE available_fqdns (
    operator TEXT,
    fqdn TEXT
);
```

## Deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/3gpp-telegram-bot.service`:

```ini
[Unit]
Description=3GPP Telegram Bot
After=network.target

[Service]
Type=simple
User=yourusername
WorkingDirectory=/path/to/sec100/telegram-bot
EnvironmentFile=/path/to/sec100/telegram-bot/.env
ExecStart=/path/to/sec100/telegram-bot/.venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable 3gpp-telegram-bot
sudo systemctl start 3gpp-telegram-bot
sudo systemctl status 3gpp-telegram-bot
```

**View logs:**
```bash
sudo journalctl -u 3gpp-telegram-bot -f
```

### Docker (Alternative)

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
```

**Build and run:**
```bash
docker build -t 3gpp-telegram-bot .
docker run -d --name 3gpp-bot --env-file .env 3gpp-telegram-bot
```

## Troubleshooting

### Bot doesn't start

**Error: `TELEGRAM_BOT_TOKEN is required`**
- Solution: Set `TELEGRAM_BOT_TOKEN` in `.env` file

**Error: `Database not found`**
- Solution: Run the 3GPP scanner first to create `database.db`
- Or run: `python3 migrations/001_add_countries.py` to verify path

### Commands don't work

**Bot responds with "Unknown command"**
- Check that handlers are registered in `main.py`
- Restart the bot

**No results returned**
- Verify database is populated: `ls -lh ../go-3gpp-scanner/bin/database.db`
- Check logs: `tail -f bot.log`

### DNS resolution is slow

- Increase `DNS_CONCURRENT_WORKERS` in `.env` (default: 10)
- Decrease `DNS_RESOLUTION_TIMEOUT` for faster failures (default: 5s)

### Rate limit issues

- Adjust `MAX_QUERIES_PER_MINUTE` and `MAX_QUERIES_PER_HOUR` in `.env`
- Add your user ID to `ADMIN_USER_IDS` to bypass limits

## Security Considerations

### For Production Use

1. **Restrict admin access** - Keep `ADMIN_USER_IDS` private
2. **Secure .env file** - Set permissions: `chmod 600 .env`
3. **Use HTTPS** - Telegram already uses TLS, but secure your server
4. **Monitor logs** - Check `bot.log` for suspicious activity
5. **Rate limiting** - Adjust limits based on your database size

### Authorized Use Only

This bot is designed for:
- ✅ Authorized security research
- ✅ Educational purposes
- ✅ Network infrastructure analysis
- ✅ Telecom industry research

**Do NOT use for:**
- ❌ Unauthorized network scanning
- ❌ Exploitation or attacks
- ❌ Privacy violations
- ❌ Service disruption

## Development

### Running Tests

```bash
# TODO: Add unit tests
pytest tests/
```

### Adding New Commands

1. Create handler in `handlers/your_handler.py`
2. Import in `main.py`
3. Register with `application.add_handler(CommandHandler("yourcommand", your_handler.your_function))`

### Code Structure

- **Handlers** (`handlers/`) - Process Telegram commands
- **Services** (`services/`) - Business logic (database, DNS, parsing)
- **Utils** (`utils/`) - Shared utilities (logging, etc.)
- **Migrations** (`migrations/`) - Database schema changes

## Contributing

This bot is part of the sec100 security research toolkit. To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

Part of the sec100 project. Use responsibly for authorized security research and educational purposes only.

## Credits

- **MCP Server** - IP resolution code adapted from `mcp-server/main.py`
- **3GPP Scanner** - Database schema from `go-3gpp-scanner` and `epdg/` tools
- **MCC-MNC List** - Data from [pbakondy/mcc-mnc-list](https://github.com/pbakondy/mcc-mnc-list)
- **phonenumbers** - Google's libphonenumber Python port
- **python-telegram-bot** - Telegram Bot API wrapper

## Support

- **Issues**: Report at [github.com/asnd/sec100/issues](https://github.com/asnd/sec100/issues)
- **Documentation**: See `CLAUDE.md` in project root
- **MCP Server**: See `mcp-server/README.md`
- **Go Scanner**: See `go-3gpp-scanner/README.md`

---

**Built with Claude Code** 🤖
