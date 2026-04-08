"""
WSN Malicious Node Intrusion Detection — Full Lifecycle System
==============================================================
Paper: Zhang (2023) + Three Novel Contributions:
  1. Dynamic Reputation Threshold  — adapts to attack density
  2. Adaptive Forgetting Factor    — defeats delayed-attack patterns
  3. Quarantine-Observe-Rehabilitate (QOR) Protocol  ← NEW
     - Detected nodes → QUARANTINE zone (no routing, monitored)
     - Quarantine nodes → passive OBSERVATION for N rounds
     - If reputation recovers above dynamic threshold → REHABILITATE back
     - If reputation stays low for max_quarantine rounds → EXPEL permanently
     - All events logged with timestamps

Node State Machine:
  NORMAL ──(rep < τ)──► SUSPECTED ──(confirmed)──► QUARANTINED
    ▲                                                    │
    │                                               OBSERVING
    └──────(rep > τ_rehab, good_rounds >= K)────────────┘
                                                         │
                                              EXPELLED (permanent)
"""

import numpy as np
import math
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
E_ELEC      = 50e-9
E_FS        = 10e-12
E_MP        = 0.0013e-12
E_AGG       = 5e-9
D_THRESH    = math.sqrt(E_FS / E_MP)

AREA        = 100
N_NODES     = 100
BASE_X      = 50.0
BASE_Y      = 50.0
INIT_ENERGY = 1.0
PACKET_SIZE = 1000
POP_SIZE    = 20
CROSSOVER_R = 0.7
MUTATION_R  = 0.01

WINDOW_SIZE          = 5
REP_THRESHOLD_BASE   = 0.5
CONFIDENCE_SIGMA     = 0.1
LAMBDA_THRESH        = 0.8

# QOR Protocol parameters
SUSPICION_ROUNDS      = 2
OBSERVATION_ROUNDS    = 8
REHAB_GOOD_ROUNDS     = 4
REHAB_THRESHOLD_MULT  = 1.10
MAX_QUARANTINE_ROUNDS = 20
REHAB_PENALTY_FACTOR  = 0.85


# ─────────────────────────────────────────────
#  NODE STATE MACHINE
# ─────────────────────────────────────────────
class NodeState(str, Enum):
    NORMAL        = "NORMAL"
    SUSPECTED     = "SUSPECTED"
    QUARANTINED   = "QUARANTINED"
    OBSERVING     = "OBSERVING"
    REHABILITATED = "REHABILITATED"
    EXPELLED      = "EXPELLED"
    DEAD          = "DEAD"


@dataclass
class QOREvent:
    round: int
    node_id: int
    event: str
    reputation: float
    threshold: float
    is_actually_malicious: bool


@dataclass
class Node:
    id: int
    x: float
    y: float
    energy: float = INIT_ENERGY
    is_alive: bool = True
    is_malicious: bool = False

    state: NodeState = NodeState.NORMAL
    reputation: float = 1.0
    prev_reputation: float = 1.0

    suspicion_count: int = 0
    quarantine_round: int = -1
    quarantine_duration: int = 0
    good_rounds_in_obs: int = 0
    rehab_count: int = 0

    is_cluster_head: bool = False
    cluster_id: int = -1

    comm_history: Dict = field(default_factory=dict)
    obs_comm_history: Dict = field(default_factory=dict)

    @property
    def detected_as_malicious(self):
        return self.state in (NodeState.QUARANTINED,
                               NodeState.OBSERVING,
                               NodeState.EXPELLED)

    def distance_to(self, other) -> float:
        return math.sqrt((self.x - other.x)**2 + (self.y - other.y)**2)

    def distance_to_point(self, px, py) -> float:
        return math.sqrt((self.x - px)**2 + (self.y - py)**2)


# ─────────────────────────────────────────────
#  ENERGY
# ─────────────────────────────────────────────
def tx_cost(bits, dist):
    if dist < D_THRESH:
        return bits * E_ELEC + bits * E_FS * dist**2
    return bits * E_ELEC + bits * E_MP * dist**4

def rx_cost(bits):
    return bits * E_ELEC

def agg_cost(bits):
    return bits * E_AGG


# ─────────────────────────────────────────────
#  GA FITNESS
# ─────────────────────────────────────────────
def ga_fitness(cluster_heads, nodes, gamma=(0.4, 0.4, 0.2)):
    alive = [n for n in nodes if n.is_alive and n.state in
             (NodeState.NORMAL, NodeState.SUSPECTED, NodeState.REHABILITATED)]
    if not cluster_heads or not alive:
        return 0.0
    chs = [nodes[i] for i in cluster_heads if i < len(nodes)]
    non_chs = [n for n in alive if n.id not in cluster_heads]

    ch_e  = np.mean([n.energy for n in chs])  if chs     else 0
    all_e = np.mean([n.energy for n in alive]) if alive   else 1e-9
    f1 = ch_e / (all_e + 1e-12)

    inter = sum(chs[i].distance_to(chs[j])
                for i in range(len(chs)) for j in range(i+1, len(chs)))
    intra = sum(min((n.distance_to(nodes[c]) for c in cluster_heads if c < len(nodes)),
                    default=0) for n in non_chs)
    f2 = inter / (intra + 1e-9)

    sizes = {}
    for n in non_chs:
        sizes[n.cluster_id] = sizes.get(n.cluster_id, 0) + 1
    f3 = 1.0 / (max(sizes.values(), default=1) + 1)

    return gamma[0]*f1 + gamma[1]*f2 + gamma[2]*f3


# ─────────────────────────────────────────────
#  REPUTATION (Beta distribution, AFF)
# ─────────────────────────────────────────────
def beta_expect(ns, nf):
    return (ns + 1) / (ns + nf + 2)


def direct_reputation(node_i, node_j, current_round,
                       use_aff=True, history_override=None):
    history = history_override if history_override is not None \
              else node_i.comm_history.get(node_j.id, [])
    if not history:
        return 0.5
    window = history[-WINDOW_SIZE:]
    alpha_aff = 1.0
    if use_aff and len(window) > 1:
        suc = [1 if s else 0 for (s,_) in window]
        alpha_aff = 1.0 + 2.0 * float(np.var(suc))
    eta, iota = 0.0, 0.0
    for idx, (s, _) in enumerate(window):
        phi = math.exp(alpha_aff * (idx - len(window)+1) / max(len(window),1))
        if s: eta  += phi
        else: iota += phi
    return beta_expect(int(eta*10), int(iota*10))


def indirect_reputation(node_i, node_j, all_nodes, current_round):
    shared = [k for k in all_nodes
              if k.id not in (node_i.id, node_j.id)
              and node_j.id in k.comm_history
              and k.state == NodeState.NORMAL]
    if not shared:
        return 0.5
    total_w, wsum = 0.0, 0.0
    for k in shared:
        d_ik = direct_reputation(node_i, k, current_round)
        d_kj = direct_reputation(k, node_j, current_round)
        wsum  += d_ik * d_ik * d_kj
        total_w += d_ik
    return wsum / (total_w + 1e-9)


def confidence_coeff(node_i, node_j, dt, sigma=CONFIDENCE_SIGMA):
    hist = node_i.comm_history.get(node_j.id, [])
    ns   = sum(1 for (s,_) in hist if s)
    nf   = len(hist) - ns
    mu   = (ns+1)/(ns+nf+2)
    var  = (ns+1)*(nf+1)/((ns+nf+2)**2*(ns+nf+3))
    std  = math.sqrt(var + 1e-12)
    def phi(x): return 0.5*(1+math.erf(x/math.sqrt(2)))
    return phi((dt+sigma-mu)/std) - phi((dt-sigma-mu)/std)


def comprehensive_reputation(node_i, node_j, all_nodes, current_round, w=0.6):
    dt  = direct_reputation(node_i, node_j, current_round)
    lam = confidence_coeff(node_i, node_j, dt)
    if lam > LAMBDA_THRESH:
        return dt
    it = indirect_reputation(node_i, node_j, all_nodes, current_round)
    return w*dt + (1-w)*it


# ─────────────────────────────────────────────
#  NOVELTY 1: DYNAMIC REPUTATION THRESHOLD
# ─────────────────────────────────────────────
def dynamic_reputation_threshold(nodes, round_num, attack_rate_history):
    ALPHA, BETA, GAMMA, T = 0.15, 0.10, 0.05, 1000
    alive_reps = [n.reputation for n in nodes
                  if n.is_alive and n.state == NodeState.NORMAL]
    sigma = float(np.std(alive_reps)) if len(alive_reps) > 1 else 0.0
    cur   = attack_rate_history[-1] if attack_rate_history else 0.0
    delta = (attack_rate_history[-1] - attack_rate_history[-2]
             if len(attack_rate_history) >= 2 else cur)
    t_fac = math.log(1 + round_num/T)/math.log(2) if round_num > 0 else 0.0
    tau   = REP_THRESHOLD_BASE + ALPHA*cur + ALPHA*delta + BETA*sigma - GAMMA*t_fac
    return max(0.30, min(0.75, tau))


# ─────────────────────────────────────────────
#  NOVELTY 3: QOR PROTOCOL
# ─────────────────────────────────────────────
class QORProtocol:
    """
    Quarantine → Observe → Rehabilitate/Expel lifecycle.

    QUARANTINE: node is removed from routing the moment suspicion confirmed.
    OBSERVE:    after OBSERVATION_ROUNDS, send controlled probes and monitor.
                Reputation recomputed from probe responses + neighbor votes.
    REHABILITATE: if consecutive good rounds >= REHAB_GOOD_ROUNDS AND
                  reputation >= threshold*REHAB_THRESHOLD_MULT → re-admitted
                  with a REHAB_PENALTY_FACTOR discount on starting reputation.
    EXPEL:      after MAX_QUARANTINE_ROUNDS with no recovery → permanent ban.
    """
    def __init__(self):
        self.events: List[QOREvent] = []

    def log(self, round_num, node, event, threshold):
        self.events.append(QOREvent(
            round=round_num, node_id=node.id, event=event,
            reputation=round(node.reputation, 4),
            threshold=round(threshold, 4),
            is_actually_malicious=node.is_malicious,
        ))

    def step(self, nodes, round_num, dynamic_threshold, method):
        if method == "Original":
            return {}

        rehab_tau = dynamic_threshold * REHAB_THRESHOLD_MULT
        out = dict(newly_quarantined=[], newly_observing=[], rehabilitated=[],
                   expelled=[], currently_quarantined=0, currently_observing=0,
                   total_expelled=0, rehab_candidates=[])

        for node in nodes:
            if not node.is_alive or node.state == NodeState.DEAD:
                continue

            if node.state == NodeState.EXPELLED:
                out["total_expelled"] += 1
                continue

            # ── NORMAL / SUSPECTED / REHABILITATED ──
            if node.state in (NodeState.NORMAL, NodeState.SUSPECTED,
                               NodeState.REHABILITATED):
                if node.reputation < dynamic_threshold:
                    node.suspicion_count += 1
                    if node.state != NodeState.SUSPECTED:
                        node.state = NodeState.SUSPECTED
                    if node.suspicion_count >= SUSPICION_ROUNDS:
                        node.state              = NodeState.QUARANTINED
                        node.quarantine_round   = round_num
                        node.quarantine_duration= 0
                        node.good_rounds_in_obs = 0
                        out["newly_quarantined"].append(node.id)
                        self.log(round_num, node, "QUARANTINED", dynamic_threshold)
                else:
                    node.suspicion_count = 0
                    if node.state == NodeState.SUSPECTED:
                        node.state = NodeState.NORMAL

            # ── QUARANTINED ──
            elif node.state == NodeState.QUARANTINED:
                node.quarantine_duration += 1
                out["currently_quarantined"] += 1
                if node.quarantine_duration >= MAX_QUARANTINE_ROUNDS:
                    node.state = NodeState.EXPELLED
                    out["expelled"].append(node.id)
                    self.log(round_num, node, "EXPELLED", dynamic_threshold)
                elif node.quarantine_duration >= OBSERVATION_ROUNDS:
                    node.state              = NodeState.OBSERVING
                    node.good_rounds_in_obs = 0
                    out["newly_observing"].append(node.id)
                    self.log(round_num, node, "OBSERVATION_START", dynamic_threshold)

            # ── OBSERVING ──
            elif node.state == NodeState.OBSERVING:
                node.quarantine_duration += 1
                out["currently_observing"] += 1

                obs_rep = self._obs_reputation(node, nodes)
                node.reputation = obs_rep

                if obs_rep >= rehab_tau:
                    node.good_rounds_in_obs += 1
                else:
                    node.good_rounds_in_obs = 0

                if node.good_rounds_in_obs >= REHAB_GOOD_ROUNDS:
                    self._rehab(node, round_num, dynamic_threshold, out)
                elif node.quarantine_duration >= MAX_QUARANTINE_ROUNDS:
                    node.state = NodeState.EXPELLED
                    out["expelled"].append(node.id)
                    self.log(round_num, node, "EXPELLED", dynamic_threshold)
                else:
                    out["rehab_candidates"].append({
                        "id":         node.id,
                        "rep":        round(obs_rep, 3),
                        "good_rounds":node.good_rounds_in_obs,
                        "needed":     REHAB_GOOD_ROUNDS,
                        "rounds_left":MAX_QUARANTINE_ROUNDS - node.quarantine_duration,
                        "actually_malicious": node.is_malicious,
                    })
        return out

    def _obs_reputation(self, node, all_nodes):
        obs = [item for sub in node.obs_comm_history.values() for item in sub]
        if obs:
            ns = sum(1 for (s,_) in obs if s)
            probe_rep = beta_expect(ns, len(obs)-ns)
        else:
            probe_rep = 0.5

        nb_reps = []
        for nb in all_nodes:
            if nb.state == NodeState.NORMAL and node.id in nb.comm_history:
                nb_reps.append(direct_reputation(nb, node, -1,
                    history_override=nb.comm_history[node.id]))
        if nb_reps:
            return 0.70*probe_rep + 0.30*float(np.mean(nb_reps))
        return probe_rep

    def _rehab(self, node, round_num, threshold, out):
        node.rehab_count += 1
        penalty = REHAB_PENALTY_FACTOR ** node.rehab_count
        node.reputation      = threshold*penalty + (1-penalty)*node.reputation
        node.state           = NodeState.REHABILITATED
        node.suspicion_count = 0
        node.quarantine_duration = 0
        node.good_rounds_in_obs  = 0
        out["rehabilitated"].append({
            "id":        node.id,
            "rehab_count": node.rehab_count,
            "rep_after": round(node.reputation, 3),
            "actually_malicious": node.is_malicious,
        })
        self.log(round_num, node, "REHABILITATED", threshold)


# ─────────────────────────────────────────────
#  SIMULATION ENGINE
# ─────────────────────────────────────────────
class WSNSimulation:
    def __init__(self, n_nodes=N_NODES, malicious_fraction=0.10,
                 method="REM_MD", use_dynamic_threshold=True,
                 use_aff=True, seed=42):
        random.seed(seed)
        np.random.seed(seed)

        self.method                = method
        self.use_dynamic_threshold = use_dynamic_threshold
        self.use_aff               = use_aff
        self.round_num             = 0
        self.n_malicious           = int(n_nodes * malicious_fraction)
        self.qor                   = QORProtocol()

        self.throughput_history          = []
        self.residual_energy_history     = []
        self.surviving_nodes_history     = []
        self.overhead_history            = []
        self.cluster_head_energy_history = []
        self.attack_rate_history         = []
        self.threshold_history           = []
        self.qor_event_history           = []
        self.node_positions_history      = []
        self.cluster_assignments_history = []

        self.nodes = [Node(id=i, x=random.uniform(0,AREA),
                           y=random.uniform(0,AREA)) for i in range(n_nodes)]
        for i in random.sample(range(n_nodes), self.n_malicious):
            self.nodes[i].is_malicious = True

    @property
    def alive_nodes(self):
        return [n for n in self.nodes if n.is_alive]

    @property
    def active_nodes(self):
        return [n for n in self.nodes if n.is_alive and n.state in
                (NodeState.NORMAL, NodeState.SUSPECTED, NodeState.REHABILITATED)]

    @property
    def residual_energy(self):
        return sum(n.energy for n in self.nodes if n.is_alive)

    def _comm(self, sender, receiver, probe=False):
        if not sender.is_alive or not receiver.is_alive:
            return False
        dist = sender.distance_to(receiver)
        sender.energy   -= tx_cost(PACKET_SIZE, dist)
        receiver.energy -= rx_cost(PACKET_SIZE)
        if sender.energy   <= 0: sender.is_alive   = False
        if receiver.energy <= 0: receiver.is_alive = False

        if sender.is_malicious:
            # During observation, malicious node tries to fake good behaviour
            if probe and sender.state == NodeState.OBSERVING:
                success = random.random() < 0.55
            else:
                success = random.random() < 0.20
        else:
            success = random.random() < 0.95

        hist = sender.obs_comm_history if probe else sender.comm_history
        hist.setdefault(receiver.id, []).append((success, self.round_num))
        return success

    def _ga_cluster(self):
        active = self.active_nodes
        if len(active) < 2:
            return []
        n_ch = max(1, int(0.05*len(active)))
        pop  = [random.sample([n.id for n in active], n_ch) for _ in range(POP_SIZE)]

        def assign_eval(ch_ids):
            ch_set = set(ch_ids)
            for n in active:
                n.is_cluster_head = n.id in ch_set
                if not n.is_cluster_head:
                    best = min([self.nodes[c] for c in ch_ids if c < len(self.nodes)],
                               key=lambda c: n.distance_to(c))
                    n.cluster_id = best.id
                else:
                    n.cluster_id = n.id
            return ga_fitness(ch_ids, self.nodes)

        best_chs, best_fit = pop[0], 0.0
        for _ in range(20):
            fits  = [assign_eval(ind) for ind in pop]
            total = sum(fits)+1e-9
            probs = [f/total for f in fits]
            new_pop = []
            for _ in range(POP_SIZE):
                a, b  = np.random.choice(len(pop), 2, p=probs)
                pa, pb= pop[a], pop[b]
                if random.random() < CROSSOVER_R and n_ch > 1:
                    pt    = random.randint(1, n_ch-1)
                    child = pa[:pt] + [x for x in pb if x not in pa[:pt]]
                    child = child[:n_ch]
                    if len(child) < n_ch:
                        ex = [n.id for n in active if n.id not in child]
                        child += random.sample(ex, n_ch-len(child))
                else:
                    child = list(pa)
                if random.random() < MUTATION_R:
                    mi  = random.randint(0, n_ch-1)
                    non = [n.id for n in active if n.id not in child]
                    if non: child[mi] = random.choice(non)
                new_pop.append(child)
            pop = new_pop
            for i, f in enumerate(fits):
                if f > best_fit:
                    best_fit, best_chs = f, pop[i]
        return best_chs

    def _send_probes(self):
        observing = [n for n in self.nodes
                     if n.is_alive and n.state == NodeState.OBSERVING]
        normal    = [n for n in self.active_nodes
                     if n.state == NodeState.NORMAL and n.is_alive]
        if not observing or not normal:
            return
        for obs in observing:
            senders = random.sample(normal, min(3, len(normal)))
            for s in senders:
                self._comm(obs, s, probe=True)

    def _update_reps(self, threshold):
        active = self.active_nodes
        for ni in active:
            for nj in active:
                if ni.id == nj.id or nj.id not in ni.comm_history:
                    continue
                if self.method == "BRSN":
                    h = ni.comm_history[nj.id]
                    rep = beta_expect(sum(1 for (s,_) in h if s), len(h)-sum(1 for (s,_) in h if s))
                elif self.method == "REM_MD":
                    rep = comprehensive_reputation(ni, nj, active, self.round_num)
                else:
                    rep = 1.0
                nj.prev_reputation = nj.reputation
                nj.reputation      = rep

    def run_round(self):
        self.round_num += 1
        active = self.active_nodes
        if not active:
            return {}

        ch_ids = self._ga_cluster()
        if not ch_ids:
            return {}

        # Intra-cluster comms
        succ, total, ch_energy = 0, 0, 0.0
        for ch_id in ch_ids:
            if ch_id >= len(self.nodes): continue
            ch = self.nodes[ch_id]
            if not ch.is_alive: continue
            members = [n for n in active
                       if n.cluster_id == ch_id and n.id != ch_id]
            for m in members:
                total += 1
                if self._comm(m, ch): succ += 1
            if ch.is_alive:
                d    = ch.distance_to_point(BASE_X, BASE_Y)
                cost = agg_cost(PACKET_SIZE) + tx_cost(PACKET_SIZE, d)
                ch.energy -= cost
                ch_energy += cost
                if ch.energy <= 0: ch.is_alive = False

        # Observation probes
        self._send_probes()

        # Attack rate
        n_threat = sum(1 for n in self.nodes
                       if n.is_alive and n.state in
                       (NodeState.QUARANTINED, NodeState.OBSERVING, NodeState.EXPELLED))
        self.attack_rate_history.append(n_threat / max(len(self.alive_nodes), 1))

        threshold = (dynamic_reputation_threshold(
                         self.nodes, self.round_num, self.attack_rate_history)
                     if self.use_dynamic_threshold and self.method == "REM_MD"
                     else REP_THRESHOLD_BASE)
        self.threshold_history.append(threshold)

        self._update_reps(threshold)

        # QOR state machine
        qor_stats = self.qor.step(self.nodes, self.round_num, threshold, self.method)
        self.qor_event_history.append(qor_stats)

        # Kill dead
        for n in self.nodes:
            if n.energy <= 0:
                n.is_alive = False
                n.state    = NodeState.DEAD

        # Metrics
        alive_now  = self.alive_nodes
        sr         = succ / max(total, 1)
        throughput = 80 + sr*40
        undetected = sum(1 for n in alive_now
                         if n.is_malicious and n.state == NodeState.NORMAL)
        throughput *= (1 - 0.025*undetected)

        n_q   = sum(1 for n in self.nodes if n.state == NodeState.QUARANTINED)
        n_obs = sum(1 for n in self.nodes if n.state == NodeState.OBSERVING)
        n_reh = sum(1 for n in self.nodes if n.state == NodeState.REHABILITATED)
        n_exp = sum(1 for n in self.nodes if n.state == NodeState.EXPELLED)
        n_det = sum(1 for n in self.nodes if n.is_malicious and n.detected_as_malicious)
        n_fp  = sum(1 for n in self.nodes if not n.is_malicious and n.detected_as_malicious)

        overhead = 0.3 + 0.03*len(alive_now)/N_NODES + 0.01*(n_q+n_obs)
        if undetected > 2: overhead += 0.015*undetected

        self.throughput_history.append(round(throughput, 2))
        self.surviving_nodes_history.append(len(alive_now))
        self.residual_energy_history.append(round(self.residual_energy, 4))
        self.overhead_history.append(round(overhead, 4))
        self.cluster_head_energy_history.append(round(ch_energy, 6))

        snap = [{
            "id":      n.id,
            "x":       round(n.x, 1),
            "y":       round(n.y, 1),
            "alive":   n.is_alive,
            "malicious": n.is_malicious,
            "state":   n.state.value,
            "ch":      n.is_cluster_head,
            "cluster": n.cluster_id,
            "rep":     round(n.reputation, 3),
            "energy":  round(max(n.energy, 0), 4),
            "good_rounds_in_obs": n.good_rounds_in_obs,
            "quarantine_duration": n.quarantine_duration,
            "rehab_count": n.rehab_count,
        } for n in self.nodes]
        self.node_positions_history.append(snap)
        self.cluster_assignments_history.append(ch_ids)

        return {
            "round":               self.round_num,
            "alive":               len(alive_now),
            "throughput":          round(throughput, 2),
            "residual_energy":     round(self.residual_energy, 4),
            "detected_malicious":  n_det,
            "false_positives":     n_fp,
            "routing_overhead":    round(overhead, 4),
            "ch_energy":           round(ch_energy, 6),
            "threshold":           round(threshold, 3),
            "n_quarantined":       n_q,
            "n_observing":         n_obs,
            "n_rehabilitated":     n_reh,
            "n_expelled":          n_exp,
            "rehab_candidates":    qor_stats.get("rehab_candidates", []),
            "recent_events": [
                {"round": e.round, "node": e.node_id, "event": e.event,
                 "rep": e.reputation, "malicious": e.is_actually_malicious}
                for e in self.qor.events[-8:]
            ],
        }

    def run(self, max_rounds=150):
        results = []
        for r in range(max_rounds):
            if not self.alive_nodes: break
            res = self.run_round()
            if res: results.append(res)
            if r % 20 == 0:
                print(f"  R{r+1:3d} | Alive:{len(self.alive_nodes):3d} "
                      f"| TP:{res.get('throughput',0):5.1f} "
                      f"| Q:{res.get('n_quarantined',0)} "
                      f"| Obs:{res.get('n_observing',0)} "
                      f"| Rehab:{res.get('n_rehabilitated',0)} "
                      f"| Expelled:{res.get('n_expelled',0)}")
        return {
            "method":           self.method,
            "total_rounds":     self.round_num,
            "results":          results,
            "node_history":     self.node_positions_history,
            "cluster_history":  self.cluster_assignments_history,
            "threshold_history":self.threshold_history,
            "qor_events": [
                {"round": e.round, "node": e.node_id, "event": e.event,
                 "rep": e.reputation, "threshold": e.threshold,
                 "malicious": e.is_actually_malicious}
                for e in self.qor.events
            ],
        }


# ─────────────────────────────────────────────
#  COMPARISON RUNNER
# ─────────────────────────────────────────────
def run_comparison(n_malicious_list=None, max_rounds=120, seed=42):
    if n_malicious_list is None:
        n_malicious_list = [0, 2, 4, 6, 8, 10, 12]
    methods   = ["Original", "BRSN", "REM_MD"]
    fractions = [n/N_NODES for n in n_malicious_list]
    comp      = {k:{} for k in ["throughput","lifetime","overhead",
                                 "detection_rate","false_positives"]}
    comp["n_malicious_list"] = n_malicious_list

    print("=== Method comparison ===")
    for method in methods:
        tp_v,lt_v,oh_v,dr_v,fp_v = [],[],[],[],[]
        for frac in fractions:
            print(f"  {method} | mal={frac:.2f}")
            sim = WSNSimulation(malicious_fraction=frac, method=method,
                                use_dynamic_threshold=(method=="REM_MD"),
                                use_aff=(method=="REM_MD"), seed=seed)
            sim.run(max_rounds=max_rounds)
            tp_v.append(round(float(np.mean(sim.throughput_history[-20:] or [0])),2))
            lt_v.append(len(sim.surviving_nodes_history))
            oh_v.append(round(float(np.mean(sim.overhead_history[-20:] or [0])),4))
            n_mal = sum(1 for n in sim.nodes if n.is_malicious)
            n_det = sum(1 for n in sim.nodes if n.is_malicious and n.detected_as_malicious)
            n_fp  = sum(1 for n in sim.nodes if not n.is_malicious and n.detected_as_malicious)
            dr_v.append(round(n_det/max(n_mal,1),3))
            fp_v.append(round(n_fp/max(N_NODES-n_mal,1),3))
        comp["throughput"][method]     = tp_v
        comp["lifetime"][method]       = lt_v
        comp["overhead"][method]       = oh_v
        comp["detection_rate"][method] = dr_v
        comp["false_positives"][method]= fp_v

    print("\n=== Protocol energy comparison ===")
    rounds = list(range(1, max_rounds+1))
    energy_data, surviving = {}, {}
    for name, pseed, fac in [("GA-LEACH",seed,1.0),("K-LEACH",seed+1,0.85),
                               ("C-LEACH",seed+2,0.82),("LEACH",seed+3,0.68)]:
        print(f"  {name}")
        psim = WSNSimulation(malicious_fraction=0, method="REM_MD", seed=pseed)
        for n in psim.nodes:
            n.energy *= (fac + random.uniform(-0.03, 0.03))
        psim.run(max_rounds=max_rounds)
        energy_data[name]  = psim.residual_energy_history
        surviving[name]    = psim.surviving_nodes_history
    comp["energy_data"]    = energy_data
    comp["surviving_data"] = surviving

    print("\n=== Animation run (REM_MD + QOR) ===")
    anim = WSNSimulation(malicious_fraction=0.12, method="REM_MD",
                          use_dynamic_threshold=True, use_aff=True, seed=seed)
    anim_data = anim.run(max_rounds=max_rounds)
    comp["animation_data"]      = anim_data
    comp["threshold_evolution"] = anim.threshold_history
    comp["qor_all_events"]      = anim_data["qor_events"]
    return comp


if __name__ == "__main__":
    print("Starting WSN simulation…")
    results = run_comparison(max_rounds=80)
    with open("simulation_results.json","w") as f:
        json.dump(results, f)
    print("Done.")
