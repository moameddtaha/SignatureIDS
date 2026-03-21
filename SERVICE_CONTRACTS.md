# SignatureIDS — Service Contracts

---

## What is a Service Contract?

A service contract is an interface that defines **what a service can do** without saying **how it does it**. The interface lives in Core (no dependencies). The implementation lives in Infrastructure or Core/Services.

This means Worker.cs never knows whether it's talking to a real SharpPcap device, a real MongoDB, or a real ONNX model. It only knows the contract. This makes each piece independently replaceable and testable.

---

## Overview

| Interface | Implemented in | Called by | Sync/Async |
|---|---|---|---|
| `IPacketCaptureService` | Infrastructure | Worker | Sync (callback) |
| `ISignatureDetectionService` | Core | Worker (Task A) | Async |
| `IFlowFeatureExtractor` | Core | Worker (Task B) | Sync |
| `IMlInferenceService` | Infrastructure | Worker (Task B) | Sync |
| `IAlertDispatcherService` | Infrastructure | Worker (both tasks) | Async |
| `IRulesSyncService` | Infrastructure | BackgroundService | Async |
| `IRulesRepository` | Infrastructure | SignatureDetectionService, RulesSyncService | Async |

---

## `IPacketCaptureService`

```csharp
public interface IPacketCaptureService : IDisposable
{
    void StartCapture(string interfaceName, Action<PacketHeaders> onPacket);
}
```

**What it does:**
Opens the specified network interface in promiscuous mode and starts listening for raw packets. For every packet that arrives, it parses the raw bytes into a `PacketHeaders` object and calls the `onPacket` callback.

**The callback pattern:**
`Action<PacketHeaders>` means you pass a method to this service and it calls your method every time a packet arrives. In Worker.cs this looks like:
```csharp
_capture.StartCapture("eth0", packet => _channel.Writer.TryWrite(packet));
```
The service doesn't decide what to do with each packet — the caller does.

**Why sync (not async):**
SharpPcap fires packet events on its own capture thread. The callback must be fast and non-blocking. All it does is write to a `Channel<PacketHeaders>` — a lock-free, synchronous operation. The async work (signature detection) happens downstream in the channel reader.

**Why `IDisposable`:**
SharpPcap holds an unmanaged handle to the network device. When the service shuts down, `Dispose()` closes the device cleanly.

**Implementation:** `Infrastructure/Services/PacketCaptureService.cs`

---

## `ISignatureDetectionService`

```csharp
public interface ISignatureDetectionService
{
    Task<DetectionResult?> DetectAsync(PacketHeaders headers);
}
```

**What it does:**
Takes a single packet and checks it against all loaded Snort rules. Returns the first rule that matches, or `null` if nothing matches.

**Matching order (early-exit):**
1. Protocol match (TCP/UDP/ICMP)
2. Destination port match
3. Content keyword match (payload inspection)

As soon as any step fails, the rule is skipped. This keeps the hot path fast.

**Return type:**
`DetectionResult?` — nullable because most packets will not match any rule. `DetectionResult` contains `bool IsMatch` and `Rule? MatchedRule`.

**Why async:**
Rules are served from `IMemoryCache`. On a cache hit it is effectively synchronous. On a cache miss (cache expired) it falls back to `IRulesRepository.GetAllEnabledAsync()` which hits MongoDB — that is genuinely async I/O.

**When it runs:** Task A in Worker.cs — called on every single packet as it arrives from the channel, in real time.

**Implementation:** `Core/Services/SignatureDetectionService.cs`

---

## `IFlowFeatureExtractor`

```csharp
public interface IFlowFeatureExtractor
{
    FlowFeatures Extract(IReadOnlyList<PacketHeaders> packets);
}
```

**What it does:**
Takes all packets collected in the 5-second window and computes the 60 statistical flow features that the ML model expects — things like average packet size, inter-arrival time, flag counts, forward/backward byte rates, and so on.

**Why `IReadOnlyList` not `IEnumerable`:**
The implementation needs to iterate the list multiple times to compute statistics (min, max, avg, std). `IReadOnlyList` guarantees random access and prevents the caller from accidentally passing a one-time-use sequence.

**Why sync:**
Pure computation — no I/O, no database, no network. Just math on the packet list. No reason to be async.

**Output:** A single `FlowFeatures` object with all 60 properties populated, ready to pass directly to `IMlInferenceService`.

**When it runs:** Task B in Worker.cs — once every 5 seconds, on the buffered packet window.

**Implementation:** `Core/Services/FlowFeatureExtractor.cs`

---

## `IMlInferenceService`

```csharp
public interface IMlInferenceService
{
    MlResult Infer(FlowFeatures features);
}
```

**What it does:**
Takes the 60 flow features, converts them to a `float[60]` array in the exact column order the model was trained on, runs them through the ONNX model in-process, and returns the predicted label.

**Return type:**
`MlResult` contains:
- `bool IsAttack` — true for anything that is not NORMAL
- `string? AttackType` — one of: `NORMAL`, `BRUTE`, `RECON`, `DOS`

**Why sync:**
ONNX inference is pure CPU computation. The model is already loaded in memory at startup. There is no I/O. Making it async would add overhead with no benefit.

**Why in Core not Infrastructure:**
The interface is in Core because it expresses a domain concept ("classify this flow"). The implementation (`OnnxInferenceService`) is in Infrastructure because it depends on the `Microsoft.ML.OnnxRuntime` NuGet package.

**When it runs:** Task B in Worker.cs — immediately after `IFlowFeatureExtractor.Extract()`, once every 5 seconds.

**Implementation:** `Infrastructure/ML/OnnxInferenceService.cs`

---

## `IAlertDispatcherService`

```csharp
public interface IAlertDispatcherService
{
    Task SendAsync(AlertDto alert);
}
```

**What it does:**
POSTs an `AlertDto` as JSON to the Dashboard API over HTTP. The Dashboard is responsible for persisting the alert and showing it to the user.

**Called from two places:**
- Task A — when a signature rule matches a packet
- Task B — when the ML model classifies a flow as an attack

Both produce an `AlertDto` and call the same method. The `DetectionSource` field on `AlertDto` is either `"Signature"` or `"ML"` so the Dashboard knows which layer caught it.

**Why async:**
HTTP is I/O. Always async.

**Why alerts are not stored here:**
This service's job is detection, not persistence. Storing alerts is the Dashboard's responsibility. Keeping it that way means this service stays stateless and focused.

**Implementation:** `Infrastructure/Services/AlertDispatcherService.cs`

---

## `IRulesSyncService`

```csharp
public interface IRulesSyncService
{
    Task SyncNowAsync(CancellationToken ct = default);
}
```

**What it does:**
Downloads the latest Snort-compatible rules from Emerging Threats, parses each rule into a `Rule` object, and upserts them into MongoDB via `IRulesRepository`.

**When it runs:**
The `RulesSyncService` implementation is a `BackgroundService` that:
1. Calls `SyncNowAsync()` once on startup to seed the database
2. Then calls it again every 7 days via `PeriodicTimer`

**Why the interface exposes `SyncNowAsync` at all:**
A `BackgroundService` could just run internally without an interface. The interface exists so that a future admin endpoint or scheduled job can trigger an immediate sync on demand without waiting for the 7-day timer.

**Why `CancellationToken ct = default`:**
The sync can take time (downloading thousands of rules). The cancellation token lets the host signal shutdown mid-sync and have the operation stop cleanly instead of being killed mid-write.

**Implementation:** `Infrastructure/Services/RulesSyncService.cs`

---

## `IRulesRepository`

```csharp
public interface IRulesRepository
{
    Task<List<Rule>> GetAllEnabledAsync();
    Task<Rule?> GetBySidAsync(int sid);
    Task UpsertAsync(Rule rule);
    Task DisableAsync(int sid);
}
```

**What it does:**
Data access layer for the rules MongoDB collection. Everything that touches the database goes through here. See `REPOSITORIES.md` for full details on each method.

**Implementation:** `Infrastructure/Repositories/RulesRepository.cs`

---

## How They Connect

```
Worker.cs
    │
    │  on startup
    ├──► IPacketCaptureService.StartCapture(iface, onPacket)
    │
    │  Task A — per packet, real-time
    ├──► ISignatureDetectionService.DetectAsync(packet)
    │        hit? ──► IAlertDispatcherService.SendAsync(alert)
    │
    │  Task B — every 5 seconds
    ├──► IFlowFeatureExtractor.Extract(packets)
    ├──► IMlInferenceService.Infer(features)
    │        attack? ──► IAlertDispatcherService.SendAsync(alert)
    │
    │  background (independent)
    └──► IRulesSyncService → IRulesRepository → MongoDB
              ▲
              └── also used by ISignatureDetectionService (cache warm)
```
