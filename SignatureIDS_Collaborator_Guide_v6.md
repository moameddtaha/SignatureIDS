# SignatureIDS — Collaborator Guide

This file contains everything you need to contribute to the SignatureIDS project.

---

## Project Overview

SignatureIDS is a .NET 10 Worker Service that captures network packets and runs two concurrent detection layers:

1. **Signature layer (per packet)** — every packet is checked against Snort rules from MongoDB. Hit → alert sent to dashboard.
2. **ML layer (per 5-second window)** — packets buffered for 5 seconds, aggregated into a flow, 60 features extracted, formatted as CSV, sent to a FastAPI ML service. Attack → alert sent to dashboard.

---

## High-Level Flow

```
Network Interface → SharpPcap → Channel<PacketHeaders>
      │
Task A (per packet):
  SignatureDetectionService → Hit? → AlertDispatcherService → Dashboard
  Always enqueue into ConcurrentQueue
      │
Task B (every 5 seconds):
  Drain queue → FlowFeatureExtractor → CsvWriter → MlForwarderService → FastAPI
  Attack? → AlertDispatcherService → Dashboard
```

---

## Tech Stack

- .NET 10 Worker Service, C#
- Clean Architecture — SignatureIDS.Worker, SignatureIDS.Core, SignatureIDS.Infrastructure
- MongoDB (rules only — alerts go to dashboard API)
- FastAPI (Python) — external ML inference service
- Serilog for structured logging

---

## Project Structure (your files highlighted)

```
SignatureIDS.Worker/
│
├── SignatureIDS.Core/
│   ├── Domain/Entity/
│   │   └── Rule.cs
│   ├── DTO/Detection/
│   │   ├── PacketHeaders.cs              # single parsed packet
│   │   ├── FlowFeatures.cs               # 60 features — input to your CsvWriter
│   │   ├── DetectionResult.cs
│   │   ├── MlResult.cs                   # output of your MlForwarderService
│   │   └── AlertDto.cs                   # input to your AlertDispatcherService
│   ├── DTO/Rules/
│   │   ├── RuleDto.cs
│   │   └── CreateRuleRequest.cs
│   └── ServiceContracts/
│       ├── IPacketCaptureService.cs
│       ├── ISignatureDetectionService.cs
│       ├── IFlowFeatureExtractor.cs
│       ├── ICsvWriter.cs                 # interface you implement
│       ├── IMlForwarderService.cs        # interface you implement
│       ├── IAlertDispatcherService.cs    # interface you implement
│       ├── IRulesSyncService.cs
│       └── Repositories/IRulesRepository.cs
│
└── SignatureIDS.Infrastructure/
    ├── Data/MongoDbContext.cs
    ├── Repositories/RulesRepository.cs
    └── Services/
        ├── PacketCaptureService.cs
        ├── SignatureDetectionService.cs
        ├── FlowFeatureExtractor.cs
        ├── CsvWriter.cs                  # YOUR FILE
        ├── MlForwarderService.cs         # YOUR FILE
        ├── RulesSyncService.cs
        └── AlertDispatcherService.cs     # YOUR FILE
```

---

## Your Tasks

Start after Mohamed Taha completes Steps 1–10. All interfaces and DTOs will exist — implement against them independently.

---

### Task 1 — CsvWriter.cs

**Location:** `SignatureIDS.Infrastructure/Services/CsvWriter.cs`

**What it does:** Takes a `FlowFeatures` object and formats all 60 values as a single comma-separated string. The string is sent to the FastAPI ML service.

**Interface to implement:**
```csharp
public interface ICsvWriter
{
    string Write(FlowFeatures features);
}
```

**Example output:**
```
20,6,64,12.5,0,1,0,0,1,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1500,40,1500,750.0,350.5,0.002,3,125000,80,1,1500,40,0,0,40,1500,20,0,65535,0,0,500000,2900,0,5800,6,0,483,966,0,483,2,0.5,0.3
```

The column order must match exactly the order in Task 1's feature table.

---

### Task 2 — MlForwarderService.cs

**Location:** `SignatureIDS.Infrastructure/Services/MlForwarderService.cs`

**What it does:** Sends the CSV row to the FastAPI ML service via HTTP POST. Returns an `MlResult` with `IsAttack` and `AttackType`.

**Interface to implement:**
```csharp
public interface IMlForwarderService
{
    Task<MlResult> ForwardAsync(string csvRow);
}
```

**Implementation:**
```csharp
public class MlForwarderService : IMlForwarderService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _config;

    public MlForwarderService(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;
        _config = config;
    }

    public async Task<MlResult> ForwardAsync(string csvRow)
    {
        var payload = new { data = csvRow };
        var response = await _httpClient.PostAsJsonAsync(
            _config["ML_API_URL"], payload);
        var result = await response.Content.ReadFromJsonAsync<MlResult>();
        return result!;
    }
}
```

The ML API URL comes from `.env` as `ML_API_URL`. Never hardcode it.

**FastAPI response format:**
```json
{
  "prediction": 1,
  "label": "RECON",
  "is_attack": true
}
```

**ML label map:**
```
0 → DOS
1 → RECON
2 → NORMAL  (benign — no alert)
3 → BRUTE
4 → ARP_SPOOFING
```

---

### Task 3 — AlertDispatcherService.cs

**Location:** `SignatureIDS.Infrastructure/Services/AlertDispatcherService.cs`

**What it does:** Sends confirmed alerts to the external dashboard API via HTTP POST. Used by both Task A (signature hit) and Task B (ML attack).

**Interface to implement:**
```csharp
public interface IAlertDispatcherService
{
    Task SendAsync(AlertDto alert);
}
```

**Implementation:**
```csharp
public class AlertDispatcherService : IAlertDispatcherService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _config;

    public AlertDispatcherService(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;
        _config = config;
    }

    public async Task SendAsync(AlertDto alert)
    {
        await _httpClient.PostAsJsonAsync(
            _config["DASHBOARD_API_URL"], alert);
    }
}
```

`AlertDto.DetectionSource` is either `"Signature"` or `"ML"` so the dashboard knows which layer caught the threat. Do not construct `new HttpClient()` — use the injected instance from `IHttpClientFactory`.

---

## Important Notes

- **Feature order matters.** The CSV column order in `CsvWriter` must match exactly the column order in `FlowFeatureExtractor`. A mismatch silently produces wrong ML predictions.
- **No alerts stored in MongoDB.** Alerts go directly to the dashboard API.
- **`FlowFeatureExtractor` takes `IReadOnlyList<PacketHeaders>`** — the full 5-second window, not a single packet.
- **Do not construct `new HttpClient()`** in `MlForwarderService` or `AlertDispatcherService` — use the injected instance.

---

## GitHub Workflow

### First time setup

```bash
git clone https://github.com/moameddtaha/SignatureIDS.git
cd SignatureIDS
```

### Before starting each task

```bash
git checkout master
git pull origin master
git checkout -b feature/your-task-name
```

Example branch names:
- `feature/flow-feature-extractor`
- `feature/csv-writer`
- `feature/ml-forwarder`
- `feature/alert-dispatcher`

### After finishing a task

```bash
git add .
git commit -m "feat: implement FlowFeatureExtractor"
git push origin feature/flow-feature-extractor
```

Open a Pull Request on GitHub. Mohamed Taha reviews and merges.

### Rules

- Never commit directly to master
- One branch per task
- Always pull from master before starting a new branch
- Only touch your own files

---

## Commit Message Format

```
feat: implement FlowFeatureExtractor
feat: implement CsvWriter
feat: implement MlForwarderService
feat: implement AlertDispatcherService
fix: correct SYN flag aggregation in FlowFeatureExtractor
```

---

## Questions

Ask Mohamed Taha about `PacketHeaders` field definitions, feature computation logic, or anything related to interfaces and DTOs.
