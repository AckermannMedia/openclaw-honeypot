# OpenClaw Honeypot

Fake OpenClaw admin panel honeypot with Illuminatus\! theme.

## Features

- Authentic OpenClaw UI clone
- Login capture with success/fail tracking
- FUCKUP chatbot (20 cryptic responses)
- Click tracking & session monitoring
- Bot vs human detection
- REST API for monitoring

## Quick Start

```bash
docker compose up -d
```

Port: `18789`

## API Endpoints

Header: `X-API-Key: YOUR_KEY`

| Endpoint | Description |
|----------|-------------|
| `/api/honeypot/stats` | Statistics |
| `/api/honeypot/logs` | All events |
| `/api/honeypot/chat-messages` | Chat logs |
| `/api/honeypot/login-attempts` | Login attempts with success field |

## Security

Container runs as non-root user with:
- Read-only rootfs
- Memory limit (256MB)
- CPU limit (0.5 cores)
- no-new-privileges

## License

MIT
