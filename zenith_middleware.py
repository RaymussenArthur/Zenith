import os
import json
import hashlib
import logging
import secrets
from typing import Optional, List, Any
from datetime import datetime, timezone

import networkx as nx
import numpy as np
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

# Logging — structured JSON logging for production observability (ELK/Datadog)
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}'
)
logger = logging.getLogger("zenith.middleware")

# FastAPI Application Initialization
app = FastAPI(
    title="Z.E.N.I.T.H. Compliance Middleware",
    description=(
        "Layer-0 B2B2G Middleware: ZK-SNARK Privacy-Preserving KYC + "
        "Temporal Graph Network Anomaly Detection for Cross-Border Settlements"
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Threat Intelligence: Known Malicious Node Registry
# In production, this would be hydrated from:
#   1. FATF (Financial Action Task Force) blacklists
#   2. OFAC SDN list (via Chainalysis/Elliptic API)
#   3. Internal threat intelligence from previous TGN detections
#
# Format: {wallet_address: {type: str, risk_weight: float, last_seen: str}}
KNOWN_MALICIOUS_NODES: dict = {
    "Mixer_Contract": {
        "type": "mixer",
        "risk_weight": 0.95,
        "description": "Tornado Cash-style mixer — breaks transaction traceability"
    },
    "Smurf_1": {
        "type": "structuring_node",
        "risk_weight": 0.88,
        "description": "Known structuring wallet — splits large transactions"
    },
    "Smurf_2": {
        "type": "structuring_node",
        "risk_weight": 0.82,
        "description": "Secondary structuring wallet in known cluster"
    },
    "LayeringHub_A": {
        "type": "layering",
        "risk_weight": 0.91,
        "description": "Multi-hop layering intermediary"
    },
}

# Hop penalty: each degree of separation from a malicious node reduces penalty
# logarithmically (inspired by PageRank decay, tuned on synthetic AML dataset)
HOP_DECAY_FACTOR = 0.65

# Web3 Configuration
# In production: use environment variables + secrets manager (AWS Secrets Manager / Vault)
WEB3_RPC_URL = os.getenv("WEB3_RPC_URL", "https://rpc-amoy.polygon.technology")
ZENITH_ESCROW_ADDRESS = os.getenv("ZENITH_ESCROW_ADDRESS", "0xd8b934580fcE35a11B58C6D73aDeE468a2833fa8")
ORACLE_PRIVATE_KEY = os.getenv("ORACLE_PRIVATE_KEY", "")
CHAIN_ID = int(os.getenv("CHAIN_ID", "80002"))  # 80002 = Polygon Amoy

# ZenithEscrow ABI (minimal — only the functions this service calls)
ZENITH_ESCROW_ABI = json.loads("""
[
  {
    "inputs": [
      {"internalType": "address payable", "name": "receiver", "type": "address"},
      {"internalType": "uint256[2]", "name": "a", "type": "uint256[2]"},
      {"internalType": "uint256[2][2]", "name": "b", "type": "uint256[2][2]"},
      {"internalType": "uint256[2]", "name": "c", "type": "uint256[2]"},
      {"internalType": "uint256[2]", "name": "publicInputs", "type": "uint256[2]"},
      {"internalType": "uint8", "name": "tgnRiskScore", "type": "uint8"},
      {"internalType": "bytes32", "name": "proofNonce", "type": "bytes32"},
      {"internalType": "uint256", "name": "transferAmount", "type": "uint256"}
    ],
    "name": "executeCrossBorderTransfer",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "name": "certificateId", "type": "bytes32"},
      {"indexed": true, "name": "sender", "type": "address"},
      {"indexed": true, "name": "receiver", "type": "address"},
      {"indexed": false, "name": "amount", "type": "uint256"},
      {"indexed": false, "name": "tgnRiskScore", "type": "uint8"},
      {"indexed": false, "name": "timestamp", "type": "uint256"},
      {"indexed": false, "name": "zkProofHash", "type": "bytes32"}
    ],
    "name": "DigitalComplianceCertificate",
    "type": "event"
  }
]
""")

def get_web3_client() -> Web3:
    """
    Dependency: returns an authenticated Web3 client connected to the target network.
    PoA middleware is injected only for PoS chains (Amoy 80002, mainnet 137).
    zkEVM chains (Cardona 2442, mainnet 1101) are pure EVM — no middleware needed.
    """
    w3 = Web3(Web3.HTTPProvider(WEB3_RPC_URL))

    # PoA middleware is required for Polygon PoS (clique consensus adds extraData field).
    # zkEVM uses standard EVM consensus — injecting PoA middleware there causes errors.
    POA_CHAIN_IDS = {137, 80002}
    if CHAIN_ID in POA_CHAIN_IDS:
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        logger.info("PoA middleware injected for chain %d", CHAIN_ID)
    else:
        logger.info("Pure EVM chain %d — no PoA middleware", CHAIN_ID)

    if not w3.is_connected():
        logger.error("Web3 connection failed to RPC: %s", WEB3_RPC_URL)
        raise HTTPException(status_code=503, detail="Blockchain node unavailable")
    return w3

# Pydantic Request/Response Models

class Groth16Proof(BaseModel):
    """Groth16 proof parameters as output by snarkjs.groth16.fullProve()"""
    pi_a: List[str] = Field(..., description="G1 point pi_a: [x, y] as decimal strings")
    pi_b: List[List[str]] = Field(..., description="G2 point pi_b: [[x1,x2],[y1,y2]] as decimal strings")
    pi_c: List[str] = Field(..., description="G1 point pi_c: [x, y] as decimal strings")
    protocol: str = Field(default="groth16", description="Proof protocol identifier")

    @validator("pi_a", "pi_c")
    def validate_g1_point(cls, v):
        # snarkjs returns 3-element arrays [x, y, "1"] — accept 2 or 3, use first 2
        if len(v) < 2:
            raise ValueError("G1 point must have at least 2 coordinates")
        return v[:2]

    @validator("pi_b")
    def validate_g2_point(cls, v):
        # snarkjs returns 3-row G2 arrays — accept 2 or 3 rows, use first 2
        if len(v) < 2:
            raise ValueError("G2 point must have at least 2 rows")
        return [row[:2] for row in v[:2]]


class ComplianceCheckRequest(BaseModel):
    """
    Compliance check request payload from the B2B client (exchange/bank/PSP).
    
    Design note: the zk_proof is included here rather than fetched separately
    because we want a single atomic API call — the client has already computed
    the proof locally (client_prover.js) and sends it with the transaction intent.
    This keeps the middleware stateless and horizontally scalable.
    """
    sender_wallet: str = Field(..., description="Sender pseudonymous wallet address")
    receiver_wallet: str = Field(..., description="Receiver pseudonymous wallet address")
    amount: float = Field(..., gt=0, description="Transfer amount in native token units")
    amount_wei: int = Field(..., gt=0, lt=10**15, description="Transfer amount in small units (amount * 1000)")
    zk_proof: Groth16Proof = Field(..., description="Groth16 proof from local prover")
    public_signals: List[str] = Field(..., description="Public signals: [result, publicThreshold]")
    transaction_metadata: Optional[dict] = Field(default={}, description="Optional B2B metadata (purpose code, corridor, etc.)")

    @validator("sender_wallet", "receiver_wallet")
    def validate_wallet_format(cls, v):
        # Accept both checksummed Ethereum addresses and human-readable test aliases
        if not (v.startswith("0x") and len(v) == 42) and not v.replace("_", "").isalnum():
            raise ValueError(f"Invalid wallet identifier: {v}")
        return v


class TGNAnalysisResult(BaseModel):
    """Output of the Temporal Graph Network analysis engine"""
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    graph_metrics: dict
    anomaly_flags: List[str]
    reasoning: str


class ComplianceCheckResponse(BaseModel):
    """Final API response with compliance verdict and on-chain settlement details"""
    status: str  # "APPROVED" | "REJECTED_ZK" | "REJECTED_TGN" | "BLOCKCHAIN_ERROR"
    transaction_hash: Optional[str]
    certificate_id: Optional[str]
    tgn_analysis: TGNAnalysisResult
    compliance_timestamp: str
    request_id: str


# TGN Graph Engine

class TemporalGraphNetworkEngine:
    """
    Simplified TGN engine for MVP. In production, this would use:
      - PyTorch Geometric's TGN implementation (Rossi et al., 2020)
      - LSTM-encoded temporal edge features
      - Mini-batch training on historical SWIFT GPI transaction data
      - Node2Vec embeddings for structural similarity

    For the MVP, we use a proximity-weighted graph traversal that captures
    the key behavioral signatures of smurfing and layering:
      1. Direct connection to known malicious nodes (immediate flag)
      2. 1-hop proximity (intermediate laundering buffer)
      3. Transaction velocity (many txns in short window = structuring signal)
      4. Fan-out ratio (high out-degree relative to in-degree = distribution)
    """

    def __init__(self, known_malicious: dict):
        self.known_malicious = known_malicious
        self.baseline_graph = self._build_baseline_threat_graph()

    def _build_baseline_threat_graph(self) -> nx.DiGraph:
        """
        Build the persistent threat topology graph from known threat intelligence.
        This represents the "prior knowledge" the TGN has accumulated from historical analysis.
        In production: hydrated from a graph database (Neo4j / Amazon Neptune).
        """
        G = nx.DiGraph()

        # Known malicious cluster topology (mirrors TGN_vis.py structure)
        G.add_node("Mixer_Contract", node_type="mixer", risk=0.95, color="salmon")
        G.add_node("Smurf_1", node_type="structuring", risk=0.88, color="salmon")
        G.add_node("Smurf_2", node_type="structuring", risk=0.82, color="salmon")
        G.add_node("LayeringHub_A", node_type="layering", risk=0.91, color="salmon")

        # Known relationships between malicious nodes
        G.add_edge("Smurf_1", "Mixer_Contract", weight=0.9, tx_count=47)
        G.add_edge("Smurf_2", "Mixer_Contract", weight=0.85, tx_count=31)
        G.add_edge("Mixer_Contract", "LayeringHub_A", weight=0.92, tx_count=12)
        G.add_edge("LayeringHub_A", "Smurf_1", weight=0.78, tx_count=8)  # Circular layering

        return G

    def analyze_transaction(
        self,
        sender: str,
        receiver: str,
        amount: float,
        transaction_history: Optional[List[dict]] = None
    ) -> TGNAnalysisResult:
        """
        Core TGN inference function:
          1. Clone baseline threat graph
          2. Add transaction nodes and edge
          3. Compute proximity score to malicious cluster
          4. Apply velocity and fan-out heuristics
          5. Synthesize into [0-100] risk score
        
        Time complexity: O(N + E) where N, E are nodes/edges in the transaction subgraph.
        For the MVP graph sizes, this is effectively O(1).
        """
        G = self.baseline_graph.copy()
        anomaly_flags = []
        risk_components = {}

        # Add transaction participants
        G.add_node(sender, node_type="wallet", risk=0.1, color="lightgreen")
        G.add_node(receiver, node_type="wallet", risk=0.1, color="lightgreen")
        G.add_edge(sender, receiver, weight=amount, tx_count=1, timestamp=datetime.now().isoformat())

        # 1: Direct Malicious Node Match 
        direct_risk = 0
        for malicious_node, attrs in self.known_malicious.items():
            if receiver == malicious_node or malicious_node.lower() in receiver.lower():
                direct_risk = attrs["risk_weight"] * 40
                anomaly_flags.append(
                    f"DIRECT_MALICIOUS_NODE: Receiver '{receiver}' matches threat node '{malicious_node}' "
                    f"(type: {attrs['type']}, risk: {attrs['risk_weight']:.2f})"
                )
                G.nodes[receiver]["risk"] = attrs["risk_weight"]
                G.nodes[receiver]["color"] = "salmon"
        risk_components["direct_malicious_proximity"] = direct_risk

        # 2: Graph Proximity Score 
        # Measure shortest path from receiver to any malicious node in the threat graph.
        # Each hop attenuates the risk signal by HOP_DECAY_FACTOR (exponential decay).
        proximity_risk = 0
        for malicious_node in self.known_malicious.keys():
            if malicious_node in G.nodes and receiver in G.nodes:
                try:
                    # Check both directions: receiver→malicious and malicious→receiver
                    try:
                        path_len = nx.shortest_path_length(G, receiver, malicious_node)
                    except nx.NetworkXNoPath:
                        try:
                            path_len = nx.shortest_path_length(G, malicious_node, receiver)
                        except nx.NetworkXNoPath:
                            continue

                    # Exponential decay: risk = base_risk * decay^hops
                    hop_risk = self.known_malicious[malicious_node]["risk_weight"] * (HOP_DECAY_FACTOR ** path_len)
                    proximity_risk = max(proximity_risk, hop_risk * 30)

                    if path_len <= 2:
                        anomaly_flags.append(
                            f"PROXIMITY_ALERT: {path_len}-hop path to '{malicious_node}' detected"
                        )
                except (nx.NodeNotFound, nx.NetworkXError):
                    continue

        risk_components["graph_proximity"] = proximity_risk

        # 3: Smurfing Pattern Detection 
        # Detect structuring: is the amount suspiciously close to common reporting thresholds?
        # FINTRAC/BNM reporting threshold: USD 10,000 / MYR 50,000 / SGD 20,000
        # Structuring: deliberate fragmentation just below these thresholds
        structuring_thresholds = [9_999, 9_500, 4_999, 2_999]  # Common structuring amounts
        structuring_risk = 0
        for threshold in structuring_thresholds:
            if threshold * 0.9 <= amount <= threshold * 1.05:
                structuring_risk = 20 * (1 - (abs(amount - threshold) / threshold))
                anomaly_flags.append(
                    f"STRUCTURING_PATTERN: Amount {amount:.2f} is within 10% of structuring threshold {threshold}"
                )
                break
        risk_components["structuring_pattern"] = structuring_risk

        # 4: Fan-out Velocity 
        # High out-degree from sender relative to in-degree indicates distribution behavior
        # For MVP: use graph degree ratio as proxy for velocity
        out_degree = G.out_degree(sender)
        in_degree = G.in_degree(sender)
        fan_out_risk = 0
        if in_degree > 0 and out_degree / in_degree > 3:
            fan_out_risk = min(10, (out_degree / in_degree) * 2)
            anomaly_flags.append(
                f"HIGH_FAN_OUT: Sender out/in degree ratio = {out_degree}/{in_degree}"
            )
        risk_components["fan_out_velocity"] = fan_out_risk

        # Synthesize Final Risk Score
        total_risk = sum(risk_components.values())
        normalized_score = min(100, int(round(total_risk)))

        # Classify risk level using tiered thresholds aligned with FATF risk ratings
        if normalized_score >= 85:
            risk_level = "CRITICAL"
        elif normalized_score >= 60:
            risk_level = "HIGH"
        elif normalized_score >= 35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Graph metrics for audit trail
        graph_metrics = {
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "sender_out_degree": out_degree,
            "sender_in_degree": in_degree,
            "risk_components": {k: round(v, 3) for k, v in risk_components.items()},
            "connected_components": nx.number_weakly_connected_components(G),
        }

        reasoning = (
            f"TGN analysis of wallet pair ({sender[:12]}…, {receiver[:12]}…): "
            f"Direct malicious match contributes {direct_risk:.1f}/40pts, "
            f"graph proximity {proximity_risk:.1f}/30pts, "
            f"structuring pattern {structuring_risk:.1f}/20pts, "
            f"fan-out velocity {fan_out_risk:.1f}/10pts. "
            f"Total: {normalized_score}/100 → {risk_level}."
        )

        return TGNAnalysisResult(
            risk_score=normalized_score,
            risk_level=risk_level,
            graph_metrics=graph_metrics,
            anomaly_flags=anomaly_flags,
            reasoning=reasoning,
        )


# Application Lifecycle: Instantiate singletons
tgn_engine = TemporalGraphNetworkEngine(known_malicious=KNOWN_MALICIOUS_NODES)

# API Endpoints

@app.get("/health", tags=["Infrastructure"])
async def health_check():
    """Liveness probe for Kubernetes/ECS health checking."""
    w3 = Web3(Web3.HTTPProvider(WEB3_RPC_URL))
    chain_connected = w3.is_connected()
    return {
        "status": "healthy",
        "version": "2.0.0",
        "chain_connected": chain_connected,
        "chain_id": CHAIN_ID if chain_connected else None,
        "tgn_threat_nodes": len(KNOWN_MALICIOUS_NODES),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post(
    "/api/v1/compliance-check",
    response_model=ComplianceCheckResponse,
    tags=["Compliance"],
    summary="Execute privacy-preserving compliance check and cross-border settlement",
)
async def compliance_check(
    request: ComplianceCheckRequest,
    x_api_key: Optional[str] = Header(None, description="B2B client API key"),
):
    """
    Core compliance orchestration endpoint.
    
    Flow:
      1. TGN graph analysis → behavioral risk score
      2. Forward ZK proof + risk score → ZenithEscrow.sol
      3. Return TX hash + Digital Compliance Certificate ID
    
    This endpoint is idempotent at the proof level — the same proof submitted
    twice will be rejected by the smart contract's replay protection.
    """
    request_id = secrets.token_hex(16)
    logger.info(
        "Compliance check initiated | request_id=%s sender=%s receiver=%s amount=%.4f",
        request_id, request.sender_wallet[:12], request.receiver_wallet[:12], request.amount
    )

    # 1: TGN Behavioral Analysis
    tgn_result = tgn_engine.analyze_transaction(
        sender=request.sender_wallet,
        receiver=request.receiver_wallet,
        amount=request.amount,
    )

    logger.info(
        "TGN analysis complete | request_id=%s risk_score=%d risk_level=%s flags=%s",
        request_id, tgn_result.risk_score, tgn_result.risk_level,
        ",".join(tgn_result.anomaly_flags) if tgn_result.anomaly_flags else "none"
    )

    # Early return if TGN already flags as critical — no need to burn gas on-chain
    if tgn_result.risk_score > 85:
        logger.warning("TGN pre-rejection | request_id=%s score=%d", request_id, tgn_result.risk_score)
        return ComplianceCheckResponse(
            status="REJECTED_TGN",
            transaction_hash=None,
            certificate_id=None,
            tgn_analysis=tgn_result,
            compliance_timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
        )

    # 2: Prepare On-Chain Transaction
    w3 = get_web3_client()

    # Convert snarkjs decimal string proof parameters to uint256 ints for Solidity
    try:
        proof = request.zk_proof
        a_params = [int(proof.pi_a[0]), int(proof.pi_a[1])]
        b_params = [
            [int(proof.pi_b[0][0]), int(proof.pi_b[0][1])],
            [int(proof.pi_b[1][0]), int(proof.pi_b[1][1])],
        ]
        c_params = [int(proof.pi_c[0]), int(proof.pi_c[1])]
        public_inputs = [int(s) for s in request.public_signals[:2]]
    except (ValueError, IndexError) as e:
        logger.error("Proof parsing failed | request_id=%s error=%s", request_id, str(e))
        raise HTTPException(status_code=422, detail=f"Proof parameter parsing error: {str(e)}")

    # Generate unique proof nonce (bytes32) — prevents replay across transactions
    proof_nonce = w3.keccak(
        text=f"{request_id}:{request.sender_wallet}:{request.receiver_wallet}:{request.amount_wei}"
    )

    # 3: Submit On-Chain
    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(ZENITH_ESCROW_ADDRESS),
            abi=ZENITH_ESCROW_ABI,
        )

        oracle_account = w3.eth.account.from_key(ORACLE_PRIVATE_KEY)
        nonce = w3.eth.get_transaction_count(oracle_account.address)

        # Build the transaction — the oracle acts as the trusted relay
        # In production: use EIP-712 typed signatures so the client authorizes
        # the oracle to call on their behalf (meta-transaction pattern)
        tx = contract.functions.executeCrossBorderTransfer(
            Web3.to_checksum_address(request.receiver_wallet)
            if request.receiver_wallet.startswith("0x") else oracle_account.address,  # testnet fallback
            a_params,
            b_params,
            c_params,
            public_inputs,
            tgn_result.risk_score,
            proof_nonce,
            request.amount_wei,
        ).build_transaction({
            "from": oracle_account.address,
            "nonce": nonce,
            "gas": 500_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": CHAIN_ID,
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key=ORACLE_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        tx_hash_hex = tx_hash.hex()

        # Extract certificate ID from event logs
        certificate_id = None
        try:
            logs = contract.events.DigitalComplianceCertificate().process_receipt(tx_receipt)
            if logs:
                certificate_id = logs[0]["args"]["certificateId"].hex()
        except Exception:
            certificate_id = hashlib.sha256(tx_hash).hexdigest()

        logger.info(
            "On-chain settlement complete | request_id=%s tx=%s cert=%s",
            request_id, tx_hash_hex[:16], certificate_id
        )

        return ComplianceCheckResponse(
            status="APPROVED" if tx_receipt.status == 1 else "BLOCKCHAIN_ERROR",
            transaction_hash=tx_hash_hex,
            certificate_id=certificate_id,
            tgn_analysis=tgn_result,
            compliance_timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
        )

    except Exception as e:
        logger.error(
            "On-chain submission failed | request_id=%s error=%s",
            request_id, str(e), exc_info=True
        )
        # Return partial result — TGN analysis succeeded even if chain tx failed
        return ComplianceCheckResponse(
            status="BLOCKCHAIN_ERROR",
            transaction_hash=None,
            certificate_id=None,
            tgn_analysis=tgn_result,
            compliance_timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
        )


@app.post("/api/v1/tgn-analyze", tags=["Compliance"], summary="TGN analysis only (no on-chain)")
async def tgn_analyze_only(
    sender_wallet: str,
    receiver_wallet: str,
    amount: float,
):
    """
    Lightweight endpoint for pre-flight TGN checks.
    B2B clients can call this before generating the ZK proof to avoid
    wasting proof-generation compute (~2-5s) on transactions that will be rejected.
    """
    result = tgn_engine.analyze_transaction(sender_wallet, receiver_wallet, amount)
    return {"tgn_analysis": result, "timestamp": datetime.now(timezone.utc).isoformat()}


# Entry Point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "zenith_middleware:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Disable in production — use gunicorn + uvicorn workers
        log_level="info",
        access_log=True,
    )