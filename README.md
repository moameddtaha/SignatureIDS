# SignatureIDS Worker

A headless **.NET 10 Worker Service** for real-time network intrusion detection. It combines **Snort-style signature matching** with a **machine learning fallback** to detect threats at wire speed, then forwards confirmed alerts to a central dashboard.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Running Locally](#running-locally)
- [Docker](#docker)
- [Logging & Observability](#logging--observability)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)

---

## How It Works

```
Network Interface
      │
      ▼
 SharpPcap — raw packet capture (promiscuous mode)
      │
      ▼
 PacketDotNet — parse Ethernet / IP / TCP / UDP layers
      │
      ▼
 SignatureDetectionService
 — match Snort rules (proto → port → content) —► HIT —► AlertDispatcherService —► Dashboard API
      │                                                                                   ▲
      │  no match                                                                         │
      ▼                                                                                   │
 FlowFeatureExtractor — compute 70 flow features                                          │
      │                                                                                   │
      ▼                                                                                   │
 MlForwarderService — HTTP POST to ML inference endpoint — attack confirmed ──────────────┘
```

The detection pipeline is **two-layered**:

1. **Signature layer** — every packet is matched against Snort-compatible rules stored in MongoDB. Rules are cached in-process with a 30-minute TTL so the hot path never hits the database. On a cache miss the service falls through to layer 2.
2. **ML layer** — 70 flow features are extracted from the packet headers, serialised to CSV, and POSTed to an external ML inference service. If the model classifies the flow as an attack, an alert is raised.

Signature rules are pulled from [Emerging Threats](https://rules.emergingthreats.net/) on first startup and automatically re-synced every 7 days.

---

## Architecture

Three-project **Clean Architecture** — dependencies only point inward:

```
SignatureIDS.Worker.slnx
├── SignatureIDS.Core            — Domain entities, DTOs, interfaces, pure service logic (zero NuGet deps)
├── SignatureIDS.Infrastructure  — MongoDB repositories, HTTP clients, RulesSyncService
└── SignatureIDS.Worker          — Composition root: DI wiring, Serilog bootstrap, hosted services
```

### Components

| Component | Layer | Responsibility |
|---|---|---|
| `Worker` | Worker | Main `BackgroundService`; owns the packet capture loop |
| `SignatureDetectionService` | Core | `MatchRule()` — early-exit matching: protocol → port → content |
| `FlowFeatureExtractor` | Core | Extracts 70 ML-ready features from packet headers |
| `CsvWriter` | Core | Serialises `FlowFeatures` to a single CSV row |
| `RulesSyncService` | Infrastructure | Seeds rules on startup; re-syncs from Emerging Threats every 7 days |
| `MlForwarderService` | Infrastructure | HTTP POST of CSV row to the ML inference endpoint |
| `AlertDispatcherService` | Infrastructure | HTTP POST of `AlertDto` to the Dashboard API |

### Data Flow — Alert Object

```
Packet captured
  → matched Rule (SID, Msg, Proto, SrcPort, DstPort, Category)
    → Alert { Timestamp, SID, Msg, SrcIp, DstIp, SrcPort, DstPort, Protocol, DetectionSource }
      → dispatched to Dashboard API (persistence is handled there)
```

`DetectionSource` is either `"Signature"` or `"ML"` so the dashboard can show which layer caught the threat.

---

## Tech Stack

| Package | Version | Purpose |
|---|---|---|
| .NET Worker SDK | 10.0 | Headless background service host |
| SharpPcap | 6.3.1 | Cross-platform raw packet capture |
| PacketDotNet | 1.4.8 | Packet dissection (Ethernet, IP, TCP, UDP) |
| MongoDB.Driver | 3.7.0 | Rules storage and caching |
| Serilog | 10.0 | Structured logging — console + rolling file sinks |
| DotNetEnv | 3.1.1 | `.env` file loading at startup |
| Microsoft.Extensions.Caching.Memory | 10.0 | In-process rule cache (30-min TTL) |

---

## Prerequisites

| Requirement | Notes |
|---|---|
| .NET 10 SDK | [dotnet.microsoft.com/download](https://dotnet.microsoft.com/download) |
| MongoDB 6+ | Self-hosted or MongoDB Atlas |
| Npcap (Windows) | [npcap.com](https://npcap.com/#download) — install in **WinPcap-compatible mode** |
| libpcap (Linux) | `sudo apt install libpcap-dev` |
| libpcap (macOS) | `brew install libpcap` |
| ML inference service | Flask or FastAPI endpoint accepting a CSV row, returning a prediction |
| Dashboard API | HTTP endpoint accepting `AlertDto` JSON payloads |

---

## Configuration

The service is configured via a `.env` file loaded at startup by DotNetEnv, combined with `appsettings.json` for log levels.

Copy `.env.example` to `.env` and fill in your values — **never commit `.env`**:

```bash
cp .env.example .env
```

| Variable | Description | Example |
|---|---|---|
| `MONGO_CONNECTION_STRING` | MongoDB connection string | `mongodb://localhost:27017` |
| `MONGO_DATABASE` | Database name | `SignatureIDS` |
| `ML_MODEL_URL` | ML inference endpoint (POST) | `http://localhost:5000/predict` |
| `DASHBOARD_API_URL` | Dashboard alert endpoint (POST) | `http://localhost:8080/api/alerts` |
| `NETWORK_INTERFACE` | Network interface to capture on | `eth0` |

> **Finding your interface name**
>
> Windows — PowerShell:
> ```powershell
> Get-NetAdapter | Select-Object Name, InterfaceDescription
> ```
> Linux:
> ```bash
> ip link show
> ```
> macOS:
> ```bash
> ifconfig
> ```

Log level and hosting settings live in `appsettings.json`. Use `appsettings.Production.json` or `appsettings.Development.json` to override per environment.

---

## Running Locally

```bash
# 1. Clone
git clone https://github.com/your-org/signatureids-worker.git
cd signatureids-worker

# 2. Configure
cp .env.example .env
# edit .env with your values

# 3. Restore & run
dotnet restore
dotnet run --project SignatureIDS.Worker
```

> **Linux / macOS** — raw packet capture requires elevated privileges:
> ```bash
> sudo dotnet run --project SignatureIDS.Worker
> ```

> **Windows** — run your terminal as Administrator, or grant Npcap capture rights to your user account in the Npcap installer settings.

On startup you will see:

```
[INF] SignatureIDS Worker starting
[INF] RulesSyncService: seeding rules from Emerging Threats...
[INF] RulesSyncService: loaded 12,483 rules into MongoDB
[INF] Rule cache warmed — 12,483 rules active
[INF] Capture started on interface eth0
```

---

## Docker

> **Why `network_mode: host` and Linux capabilities?**
>
> SharpPcap opens a raw socket directly on a physical network interface. Docker's default bridge network hides host interfaces from the container. `network_mode: host` makes them visible. `NET_ADMIN` and `NET_RAW` allow the process to set the interface to promiscuous mode and read raw frames.
>
> These options are **Linux only**. On Windows/macOS, Docker Desktop runs a Linux VM — the container sees the VM's virtual interfaces, not your physical ones. Use a Linux host for production.

---

### Option A — docker run

Build from the solution root:

```bash
docker build \
  -f SignatureIDS.Worker/Dockerfile \
  -t signatureids-worker:latest \
  .
```

Run in the foreground (useful for testing):

```bash
docker run --rm \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --env-file .env \
  signatureids-worker:latest
```

Run detached in production:

```bash
docker run -d \
  --name signatureids-worker \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --env-file .env \
  signatureids-worker:latest
```

Day-to-day:

```bash
docker logs -f signatureids-worker     # stream live logs
docker stop signatureids-worker        # graceful shutdown
docker start signatureids-worker       # restart
docker rm signatureids-worker          # remove container (image kept)
```

---

### Option B — Docker Compose (recommended)

`docker-compose.yml` is included in the repository root. It starts the worker and a MongoDB instance together, with a healthcheck so the worker only starts once MongoDB is ready.

```bash
cp .env.example .env
# edit .env — set MONGO_CONNECTION_STRING=mongodb://mongodb:27017 when using Compose

docker compose up --build -d           # build and start everything detached
docker compose up --build              # same, stream logs to terminal
```

Common operations:

```bash
docker compose ps                      # container status and health
docker compose logs -f worker          # live worker logs
docker compose logs -f mongodb         # live MongoDB logs
docker compose restart worker          # restart worker only (MongoDB stays up)
docker compose stop                    # stop everything (data preserved)
docker compose down                    # stop and remove containers (data preserved)
docker compose down -v                 # also delete MongoDB volume — resets all data
```

Rebuild after a code change without touching MongoDB:

```bash
docker compose up --build -d worker
```

---

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Operation not permitted` on capture open | Missing Linux capabilities | Add `--cap-add NET_ADMIN --cap-add NET_RAW` |
| `Interface 'eth0' not found` | Wrong interface name in `.env` | List interfaces: `docker run --rm --network host signatureids-worker:latest ip link show` |
| Worker exits immediately after start | MongoDB not ready | Check `docker compose ps` — wait for `mongodb` to show `healthy` |
| `Connection refused` to ML / Dashboard | Wrong URL or service not running | Check `ML_MODEL_URL` / `DASHBOARD_API_URL` in `.env` |
| Rules not loading | No outbound internet access | Check host firewall; run `docker compose logs worker` for details |
| High CPU on first start | Initial Emerging Threats sync | Normal — settles once the rule download completes |

---

## Logging & Observability

Serilog emits structured logs to two sinks simultaneously:

| Sink | Format | Location |
|---|---|---|
| Console | JSON (structured) | Captured by Docker log driver — pipe to Loki, Fluentd, or CloudWatch |
| Rolling file | Plain text | `logs/signatureids-YYYYMMDD.log` — rotates daily, kept 7 days |

Every log entry for a detected threat includes:

```json
{
  "Timestamp": "2025-11-14T08:32:11.442Z",
  "Level": "Warning",
  "Message": "Threat detected",
  "SID": 2019284,
  "Msg": "ET SCAN Nmap SYN Scan",
  "SrcIp": "192.168.1.45",
  "DstIp": "10.0.0.1",
  "Protocol": "TCP",
  "DetectionSource": "Signature"
}
```

To ship logs to a central system add a Serilog sink package to `SignatureIDS.Worker.csproj` (e.g. `Serilog.Sinks.Seq`, `Serilog.Sinks.Elasticsearch`, `Serilog.Sinks.Grafana.Loki`) and configure it in `Program.cs`.

---

## Security Considerations

- **Never commit `.env`** — it is listed in `.gitignore`. Use `.env.example` for documentation.
- **MongoDB is bound to loopback only** (`127.0.0.1:27017`) in the Compose file. Never expose MongoDB publicly. In production use a private network or MongoDB Atlas with IP allowlisting.
- **The container runs as a non-root user** (`$APP_UID` set by the Dockerfile base image). Do not override this to `root`.
- **`NET_ADMIN` and `NET_RAW` are powerful capabilities** — limit their use to trusted hosts and restrict the container's filesystem to read-only where possible.
- **Treat connection strings and API keys as secrets** — in production, source them from a secrets manager (HashiCorp Vault, AWS Secrets Manager, Docker Secrets) rather than a plain `.env` file.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Keep commits focused — one logical change per commit
4. Ensure the solution builds cleanly: `dotnet build`
5. Open a pull request with a clear description of what changed and why

Do not commit `.env`, `bin/`, or `obj/` directories.


