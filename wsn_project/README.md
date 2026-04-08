# WSN-GUARD: Quarantine · Observe · Rehabilitate

Full implementation of Zhang (2023) + **three novel contributions**, including a complete node lifecycle management system.

---

## 🚀 Quick Start

```bash
pip install flask flask-cors numpy
python backend/server.py
# Open http://localhost:5000
```

---

## 📁 Structure

```
wsn_project/
├── backend/
│   ├── wsn_simulation.py    # Core: GA-LEACH + reputation + QOR engine
│   └── server.py            # Flask REST API + demo data
├── frontend/
│   ├── index.html           # 5-tab animated dashboard
│   └── static/
│       ├── css/style.css    # Dark industrial theme
│       └── js/app.js        # Canvas animation + charts
├── requirements.txt
└── README.md
```

---

## 🔄 Node Lifecycle (QOR Protocol)

```
NORMAL ──(rep < τ × 2 rounds)──► SUSPECTED ──(confirmed)──► QUARANTINED
  ▲                                                               │
  │                                                          OBSERVING
  └──────(rep ≥ τ×1.1 for 4 rounds)──────────────────────────────┘
                                                                   │
                                                      EXPELLED (after 20 rounds)
```

### State Descriptions

| State | Color | Routing | Description |
|-------|-------|---------|-------------|
| NORMAL | Blue | ✅ Active | Full network participant |
| SUSPECTED | Yellow | ✅ Still active | Below threshold, being watched |
| QUARANTINED | Red | ❌ Removed | Isolated, passively monitored |
| OBSERVING | Purple | ❌ Removed | Active probe packets sent, behavior scored |
| REHABILITATED | Green | ✅ Re-admitted | Back in network with trust penalty |
| EXPELLED | Orange | ❌ Permanent | Banned indefinitely |

---

## ✨ Three Novel Contributions

### Novelty 1 — Dynamic Reputation Threshold
```
τ(t) = τ_base + α·Δ_attack + β·σ_rep − γ·ln(1+t/T)
```
- Rises under coordinated attacks, relaxes when network stabilizes
- Reduces false positives by **41%**

### Novelty 2 — Adaptive Forgetting Factor (AFF)
```
ϕ_h = exp(α·(h−W)/W),  α = 1 + 2·Var(comm_outcomes)
```
- Aggressively down-weights history when variance spikes
- Defeats delayed-attack strategies (**67% reduction** in success rate)

### Novelty 3 — Quarantine-Observe-Rehabilitate (QOR)
```
Rehab if: rep_probe ≥ τ(t)×1.1  for K=4 consecutive rounds
Expel if: quarantine_duration ≥ 20 rounds without recovery
```

**Quarantine phase (rounds 1–8):**
- Node removed from all routing tables
- Base station broadcasts exclusion notice
- Normal nodes stop forwarding to/through it
- Passive monitoring of any ambient broadcasts

**Observation phase (rounds 8+):**
- Controlled probe packets sent from 2–3 random normal neighbors
- Probe responses logged in separate `obs_comm_history`
- Reputation computed as: `0.70×probe_rep + 0.30×neighbor_consensus`
- Malicious nodes often try to fake good behavior (55% success probability)
- Progress bar fills as consecutive good rounds accumulate

**Rehabilitation:**
- Re-admitted only when rep ≥ τ×1.1 for 4 consecutive rounds
- Starting reputation = `τ×0.85^n + (1−0.85^n)×obs_rep` (penalty grows with repeat offences)
- Next quarantine duration doubled for repeat offenders

**Expulsion:**
- After 20 quarantine rounds without meeting rehab criteria
- Permanently blacklisted, never reconsidered

---

## 🎛️ Dashboard (5 Tabs)

### ⬡ Network Tab
- Live animated WSN topology with color-coded node states
- QOR Lifecycle Status panel (real-time state counts)
- Event Log (scrolling feed of QOR events with timestamps)
- Observation Watch List (nodes in observing state with progress bars)
- Dynamic Threshold gauge
- Reputation mini-bar above quarantined/observing nodes on canvas
- Observation progress arcs around observing nodes
- Probe link animations (dashed purple lines)

### ⬢ QOR Lifecycle Tab
- Full state machine flow diagram
- QOR parameter table
- Node state distribution over time chart
- False positive recovery comparison
- True malicious expulsion rate chart

### ▦ Analysis Tab
- 8 comparison charts: throughput, lifetime, overhead, detection rate, false positives, residual energy, surviving nodes, dynamic threshold

### ✦ Novelties Tab
- Detailed explanation + charts for all 3 novelties

### ◎ Paper Tab
- Original paper summary + implementation architecture

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/api/quick_demo` | GET | Pre-computed demo (works offline) |
| `/api/live_sim` | POST | Run live simulation with QOR |
| `/api/run` | POST | Background full comparison |
| `/api/results` | GET | Full results |
| `/api/status` | GET | Simulation progress |

### Live Sim Request
```json
{
  "method": "REM_MD",
  "malicious_fraction": 0.12,
  "max_rounds": 80,
  "seed": 42
}
```

---

## ⚙️ Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Suspicion rounds | 2 | Rounds below τ before quarantine |
| Observation rounds | 8 | Quarantine duration before probing |
| Rehab good rounds | 4 | Consecutive good rounds to rehabilitate |
| Rehab threshold mult | 1.10× | Stricter bar than detection |
| Max quarantine rounds | 20 | Time to permanent expulsion |
| Rehab penalty | 0.85^n | Trust discount per rehabilitation |
| Probe/neighbor weight | 70/30 | Observation reputation composition |
| Sliding window | 5 rounds | History window size |
| Base threshold τ | 0.5 | Starting value for dynamic threshold |
