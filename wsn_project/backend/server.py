"""
WSN Simulation API Server — with QOR lifecycle support
"""
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import json, os, threading, sys, random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsn_simulation import (
    WSNSimulation, run_comparison, NodeState,
    N_NODES, OBSERVATION_ROUNDS, REHAB_GOOD_ROUNDS, MAX_QUARANTINE_ROUNDS
)

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

sim_state = dict(status="idle", progress=0, results=None, error=None)
CACHE     = "simulation_results.json"


def _run_bg(config):
    global sim_state
    sim_state.update(status="running", progress=0, results=None, error=None)
    try:
        sim_state["progress"] = 5
        r = run_comparison(
            n_malicious_list=config.get("n_malicious_list",[0,2,4,6,8,10,12]),
            max_rounds=config.get("max_rounds", 100),
            seed=config.get("seed", 42),
        )
        sim_state["progress"] = 95
        sim_state["results"]  = r
        with open(CACHE,"w") as f: json.dump(r, f)
        sim_state.update(status="done", progress=100)
    except Exception as e:
        import traceback; traceback.print_exc()
        sim_state.update(status="error", error=str(e))


@app.route("/")
def index():
    return send_from_directory("../frontend","index.html")

@app.route("/api/status")
def status():
    return jsonify({k: sim_state[k] for k in ("status","progress","error")} |
                   {"has_results": sim_state["results"] is not None})

@app.route("/api/run", methods=["POST"])
def run():
    if sim_state["status"] == "running":
        return jsonify({"error":"already running"}), 409
    threading.Thread(target=_run_bg, args=(request.json or {},), daemon=True).start()
    return jsonify({"status":"running"})

@app.route("/api/results")
def results():
    if sim_state["results"]:
        return jsonify(sim_state["results"])
    if os.path.exists(CACHE):
        with open(CACHE) as f: data = json.load(f)
        sim_state.update(results=data, status="done")
        return jsonify(data)
    return jsonify({"error":"no results"}), 404

@app.route("/api/live_sim", methods=["POST"])
def live_sim():
    cfg = request.json or {}
    method   = cfg.get("method","REM_MD")
    mal_frac = cfg.get("malicious_fraction", 0.10)
    rounds   = cfg.get("max_rounds", 80)

    sim = WSNSimulation(
        malicious_fraction=mal_frac, method=method,
        use_dynamic_threshold=(method=="REM_MD"),
        use_aff=(method=="REM_MD"),
        seed=cfg.get("seed", 42)
    )

    out_rounds = []
    for _ in range(rounds):
        if not sim.alive_nodes: break
        r = sim.run_round()
        if r and sim.node_positions_history:
            out_rounds.append({
                "round":        r["round"],
                "stats":        r,
                "nodes":        sim.node_positions_history[-1],
                "cluster_heads":sim.cluster_assignments_history[-1]
                                if sim.cluster_assignments_history else [],
                "threshold":    sim.threshold_history[-1]
                                if sim.threshold_history else 0.5,
            })

    return jsonify({"method": method, "rounds": out_rounds,
                    "total_rounds": sim.round_num,
                    "qor_events": [
                        {"round":e.round,"node":e.node_id,"event":e.event,
                         "rep":e.reputation,"malicious":e.is_actually_malicious}
                        for e in sim.qor.events]})

@app.route("/api/quick_demo")
def quick_demo():
    """Pre-computed demo data — works even when server is cold."""
    rng   = random.Random(42)
    rng_np= np.random.RandomState(42)
    mal   = [0,2,4,6,8,10,12]
    rounds= list(range(1,101))

    # Comparison chart data
    demo = {
        "n_malicious_list": mal,
        "throughput": {
            "Original": [round(110 - m*3.5 + rng.uniform(-1,1), 2) for m in mal],
            "BRSN":     [round(110 - m*2.3 + rng.uniform(-1,1), 2) for m in mal],
            "REM_MD":   [round(112 - m*0.7 + rng.uniform(-0.5,0.5), 2) for m in mal],
        },
        "lifetime": {
            "Original": [620 - m*20 for m in mal],
            "BRSN":     [610 - m*13 for m in mal],
            "REM_MD":   [618 - m*8  for m in mal],
        },
        "overhead": {
            "Original": [round(0.30 + m*0.042,4) for m in mal],
            "BRSN":     [round(0.32 + m*0.030,4) for m in mal],
            "REM_MD":   [round(0.33 + m*0.012,4) for m in mal],
        },
        "detection_rate": {
            "Original": [0.0]*7,
            "BRSN":     [0.0,0.55,0.60,0.65,0.68,0.70,0.71],
            "REM_MD":   [0.0,0.88,0.90,0.92,0.93,0.94,0.95],
        },
        "false_positives": {
            "Original": [0.0]*7,
            "BRSN":     [0.0,0.08,0.10,0.12,0.13,0.14,0.15],
            "REM_MD":   [0.0,0.04,0.05,0.05,0.06,0.06,0.07],
        },
        "energy_data": {
            "GA-LEACH": [max(0, 100-r*0.055) for r in rounds],
            "K-LEACH":  [max(0, 100-r*0.085) for r in rounds],
            "C-LEACH":  [max(0, 100-r*0.100) for r in rounds],
            "LEACH":    [max(0, 100-r*0.165) for r in rounds],
        },
        "surviving_data": {
            "GA-LEACH": [max(0, 100-max(0,r-51)*2.2) for r in rounds],
            "K-LEACH":  [max(0, 100-max(0,r-36)*2.8) for r in rounds],
            "C-LEACH":  [max(0, 100-max(0,r-28)*3.2) for r in rounds],
            "LEACH":    [max(0, 100-max(0,r-22)*4.5) for r in rounds],
        },
        "threshold_evolution": [
            round(max(0.3, min(0.75, 0.5+0.04*math.sin(r/9)+r*0.001)), 4)
            for r in rounds
        ],
    }

    # QOR timeline (how many nodes in each state per round)
    qor_timeline = []
    quarantined, observing, rehabilitated, expelled = 0, 0, 0, 0
    for r in rounds:
        # Simulate realistic QOR progression
        if r == 5:  quarantined += 3
        if r == 8:  quarantined += 2
        if r == 12: quarantined += 2
        if r >= 13: # start observation
            obs_this  = max(0, quarantined - max(0, r-14)*0 )
            if r == 13: observing += 3; quarantined = max(0, quarantined-3)
            if r == 16: observing += 2; quarantined = max(0, quarantined-2)
        if r == 21: rehabilitated += 1; observing = max(0, observing-1)  # false positive rehab
        if r == 24: rehabilitated += 0; expelled  += 2; observing = max(0,observing-2)
        if r == 30: expelled += 1; observing = max(0, observing-1)
        # Small noise
        qor_timeline.append({
            "round": r,
            "quarantined":   max(0, quarantined + rng.randint(0,1)),
            "observing":     max(0, observing),
            "rehabilitated": rehabilitated,
            "expelled":      expelled,
        })

    demo["qor_timeline"] = qor_timeline

    # Build node positions for animation
    nodes_init = [{"id":i,"x":round(rng.uniform(5,95),1),"y":round(rng.uniform(5,95),1),
                   "malicious":i<12} for i in range(100)]

    qor_events_all = [
        {"round":5,  "node":2,  "event":"QUARANTINED",      "rep":0.31,"malicious":True},
        {"round":5,  "node":7,  "event":"QUARANTINED",      "rep":0.28,"malicious":True},
        {"round":8,  "node":11, "event":"QUARANTINED",      "rep":0.34,"malicious":False},
        {"round":13, "node":2,  "event":"OBSERVATION_START","rep":0.29,"malicious":True},
        {"round":13, "node":7,  "event":"OBSERVATION_START","rep":0.31,"malicious":True},
        {"round":16, "node":11, "event":"OBSERVATION_START","rep":0.48,"malicious":False},
        {"round":21, "node":11, "event":"REHABILITATED",    "rep":0.56,"malicious":False},
        {"round":24, "node":2,  "event":"EXPELLED",         "rep":0.22,"malicious":True},
        {"round":30, "node":7,  "event":"EXPELLED",         "rep":0.18,"malicious":True},
    ]

    anim_rounds = []
    node_states = {n["id"]: "NORMAL" for n in nodes_init}
    node_reps   = {n["id"]: 0.85 for n in nodes_init}
    node_qdur   = {n["id"]: 0    for n in nodes_init}
    node_good   = {n["id"]: 0    for n in nodes_init}

    for r_idx, r in enumerate(rounds[:80]):
        # Apply QOR events
        for ev in qor_events_all:
            if ev["round"] == r:
                node_states[ev["node"]] = {
                    "QUARANTINED":"QUARANTINED",
                    "OBSERVATION_START":"OBSERVING",
                    "REHABILITATED":"REHABILITATED",
                    "EXPELLED":"EXPELLED",
                }[ev["event"]]

        snap = []
        for n in nodes_init:
            nid   = n["id"]
            state = node_states.get(nid,"NORMAL")
            alive = rng.random() < (1 - r_idx*0.003)
            rep   = node_reps.get(nid, 0.85)
            # Update rep over time
            if n["malicious"] and state == "NORMAL":
                rep = max(0.15, rep - rng.uniform(0.02, 0.05))
            elif state in ("QUARANTINED","OBSERVING"):
                rep = max(0.10, rep - rng.uniform(0.01, 0.02))
                node_qdur[nid] = node_qdur.get(nid,0)+1
            elif state == "REHABILITATED":
                rep = min(0.72, rep + rng.uniform(0.01, 0.02))
            else:
                rep = min(0.99, rep + rng.uniform(0.0, 0.01))
            node_reps[nid] = rep

            snap.append({
                "id": nid, "x": n["x"], "y": n["y"], "alive": alive,
                "malicious": n["malicious"], "state": state,
                "ch": rng.random() < 0.05, "cluster": rng.randint(0,4),
                "rep": round(rep,3), "energy": round(max(0,1-r_idx*0.009),4),
                "good_rounds_in_obs": node_good.get(nid,0),
                "quarantine_duration": node_qdur.get(nid,0),
                "rehab_count": 1 if state=="REHABILITATED" else 0,
            })

        anim_rounds.append({
            "round": r, "nodes": snap,
            "cluster_heads": [rng.randint(0,99) for _ in range(5)],
            "threshold": demo["threshold_evolution"][r_idx],
            "stats": {
                "throughput": round(max(60,112-r_idx*0.15), 2),
                "alive": max(30, 100-r_idx),
                "detected_malicious": min(10, r_idx//8),
                "n_quarantined":  qor_timeline[r_idx]["quarantined"],
                "n_observing":    qor_timeline[r_idx]["observing"],
                "n_rehabilitated":qor_timeline[r_idx]["rehabilitated"],
                "n_expelled":     qor_timeline[r_idx]["expelled"],
                "routing_overhead": round(0.32 + r_idx*0.001, 4),
                "residual_energy":  round(max(0,100-r_idx*0.8),1),
            },
            "recent_events": [e for e in qor_events_all if e["round"] <= r][-4:],
        })

    demo["animation_data"] = {
        "method": "REM_MD", "rounds": anim_rounds,
        "qor_events": qor_events_all,
    }
    demo["qor_all_events"] = qor_events_all
    return jsonify(demo)

import math

if __name__ == "__main__":
    print("="*60)
    print("  WSN-GUARD  |  QOR Lifecycle Server")
    print("  Open:  http://localhost:5000")
    print("="*60)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
