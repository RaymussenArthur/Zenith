# Z.E.N.I.T.H.
### Zero-knowledge Encrypted Network for Inference & Temporal Heuristics

> **Layer-0 B2B2G Middleware** — Privacy-Preserving Compliance via ZK-SNARKs (Groth16) + Real-time Smurfing/Layering Detection via Temporal Graph Networks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Solidity 0.8](https://img.shields.io/badge/Solidity-0.8.20-purple.svg)](https://soliditylang.org/)
[![Circom 2.1.6](https://img.shields.io/badge/Circom-2.1.6-green.svg)](https://docs.circom.io/)

---

## What is Z.E.N.I.T.H.?

Traditional AML/KYC compliance forces financial institutions to expose raw customer data to third-party services — creating GDPR conflicts, data sovereignty issues, and honeypot attack surfaces.

**Z.E.N.I.T.H. solves the Data-Sharing vs. Privacy paradox** using two cryptographic layers:

| Layer | Technology | What It Does |
|---|---|---|
| **Layer 1 — Identity Compliance** | ZK-SNARK (Groth16) | Proves KYC predicate is satisfied *without* revealing the underlying data |
| **Layer 2 — Behavioral Compliance** | Temporal Graph Network | Detects smurfing, layering, and mixer usage via spatio-temporal wallet graph analysis |

Both layers are enforced **atomically on-chain** in a single transaction — eliminating TOCTOU attack surfaces.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    B2B Client (Exchange/Bank)                │
│                       client_prover.js                       │
│  • Loads input.json (secretData stays LOCAL, never sent)     │
│  • Generates Groth16 ZK proof via snarkjs locally (~1-2s)    │
│  • POSTs proof + transaction intent to middleware API        │
└──────────────────────────┬──────────────────────────────────┘
                           │ POST /api/v1/compliance-check
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Z.E.N.I.T.H. Middleware (FastAPI)               │
│                   zenith_middleware.py                       │
│  • TGN Graph Engine: builds wallet interaction graph         │
│  • Scores behavioral risk 0-100 across 4 signal components   │
│  • Forwards ZK proof + risk score → blockchain oracle        │
└──────────────────────────┬──────────────────────────────────┘
                           │ web3.py → executeCrossBorderTransfer()
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           ZenithEscrow.sol (Polygon zkEVM / Amoy)            │
│  • Verifies Groth16 proof via Groth16Verifier (O(1) pairing) │
│  • Checks TGN risk score < 85 threshold                      │
│  • Emits DigitalComplianceCertificate event                  │
│  • Executes atomic fund transfer from escrow                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
ZENITH/
├── compliance_circuit.circom        # ZK circuit: proves secretData * threshold = result
├── compliance_circuit.zkey          # Groth16 proving key (generated, not committed)
├── compliance_circuit.r1cs          # R1CS constraint system
├── compliance_circuit_js/
│   ├── compliance_circuit.wasm      # Compiled circuit (witness generation)
│   ├── generate_witness.js          # snarkjs witness generator
│   └── witness_calculator.js        # snarkjs witness calculator
├── input.json                       # Circuit input: {secretData, publicThreshold}
├── public.json                      # Public signals output: [result, threshold]
├── proof.json                       # Sample generated proof
├── verification_key.json            # Groth16 verification key
├── witness.wtns                     # Generated witness (binary)
├── pot12_0000.ptau                  # Powers of Tau ceremony file
├── pot12_0001.ptau                  # Powers of Tau (contributed)
├── pot12_final.ptau                 # Powers of Tau (final)
│
├── Verifier.sol                     # Auto-generated Groth16 verifier (snarkjs export)
├── ZenithEscrow.sol                 # Main compliance escrow smart contract
│
├── zenith_middleware.py             # FastAPI microservice: TGN engine + web3 oracle
├── client_prover.js                 # B2B client SDK: local proof generation + API call
├── TGN_vis.py                       # Phase 1: static TGN visualization (networkx)
│
├── Dockerfile                       # Multi-stage optimized container for middleware
├── requirements.txt                 # Python dependencies
├── package.json                     # Node.js dependencies
├── .env.example                     # Environment variable template
└── README.md
```

---

## Phase 1 — Local Proof of Concept (Completed)

Built the ZK circuit and verified proof generation locally:

```bash
# Compile circuit
circom compliance_circuit.circom --r1cs --wasm --sym

# Powers of Tau ceremony
npx snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
npx snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau
npx snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau

# Groth16 setup
npx snarkjs groth16 setup compliance_circuit.r1cs pot12_final.ptau compliance_circuit.zkey

# Generate & verify proof
npx snarkjs groth16 fullprove input.json compliance_circuit_js/compliance_circuit.wasm compliance_circuit.zkey proof.json public.json
npx snarkjs groth16 verify verification_key.json public.json proof.json
```

**Circuit:** `result <== secretData * publicThreshold` — proves the multiplication was done correctly without revealing `secretData`.

---

## Phase 2 — Testnet MVP Orchestration (Completed)

### Prerequisites

```bash
# Node.js dependencies
npm install snarkjs axios

# Python dependencies
pip install fastapi uvicorn[standard] web3 networkx numpy pydantic httpx

# Generate Verifier.sol from zkey
npx snarkjs zkey export solidityverifier compliance_circuit.zkey Verifier.sol
```

### Environment Setup

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

### Start the Middleware

```bash
uvicorn zenith_middleware:app --host 0.0.0.0 --port 8000 --reload
```

Verify it's running:
```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy","chain_connected":true,"chain_id":2442,...}
```

### Deploy Smart Contracts (Remix IDE)

1. Open [remix.ethereum.org](https://remix.ethereum.org)
2. Upload `Verifier.sol` and `ZenithEscrow.sol`
3. Compile both with Solidity **0.8.20**
4. Deploy `Groth16Verifier` first → copy address
5. Deploy `ZenithEscrow` with the verifier address as `_verifier` parameter
6. Update `ZENITH_ESCROW_ADDRESS` in your `.env`

**Deployed on:** Remix VM (local EVM) / Polygon zkEVM Cardona (chain ID 2442) / Polygon Amoy (chain ID 80002)

### Run the B2B Client Prover

```bash
node client_prover.js
# With custom params:
node client_prover.js --sender "0xExchangeWallet" --receiver "0xBankWallet" --amount 5000
```

---

## API Reference

### `GET /health`
System liveness check — returns chain connection status and TGN threat node count.

### `POST /api/v1/compliance-check`
Main compliance orchestration endpoint.

**Request:**
```json
{
  "sender_wallet": "Wallet_A_Exchange",
  "receiver_wallet": "Wallet_B_Bank",
  "amount": 5000,
  "amount_wei": 5000000,
  "zk_proof": {
    "pi_a": ["...", "..."],
    "pi_b": [["...", "..."], ["...", "..."]],
    "pi_c": ["...", "..."],
    "protocol": "groth16"
  },
  "public_signals": ["123456000", "1000"]
}
```

**Response:**
```json
{
  "status": "APPROVED",
  "transaction_hash": "0x...",
  "certificate_id": "0x...",
  "tgn_analysis": {
    "risk_score": 20,
    "risk_level": "LOW",
    "anomaly_flags": ["STRUCTURING_PATTERN: Amount 5000.00 is within 10% of structuring threshold 4999"],
    "graph_metrics": {"nodes": 6, "edges": 5}
  }
}
```

**Status codes:**

| Status | Meaning |
|---|---|
| `APPROVED` | ZK proof valid + TGN score ≤ 85 + on-chain settlement successful |
| `REJECTED_ZK` | Groth16 proof verification failed |
| `REJECTED_TGN` | TGN behavioral risk score > 85 (smurfing/layering detected) |
| `BLOCKCHAIN_ERROR` | ZK + TGN passed but blockchain submission failed |

### `POST /api/v1/tgn-analyze`
Lightweight pre-flight TGN check without proof submission — use to avoid wasting proof generation compute on high-risk transactions.

### `GET /api/docs`
Interactive Swagger UI.

---

## TGN Risk Scoring

The Temporal Graph Network engine scores transactions across 4 independent signal components:

| Component | Max Points | Detects |
|---|---|---|
| Direct malicious node match | 40 | Receiver is a known mixer/smurf wallet |
| Graph proximity (hop decay) | 30 | 1-2 hop distance to malicious cluster |
| Structuring pattern | 20 | Amount near AML reporting thresholds |
| Fan-out velocity | 10 | High out/in degree ratio (distribution pattern) |

**Threshold:** Score > 85 → `REJECTED_TGN` (revert on-chain: `Z.E.N.I.T.H: TGN Anomaly Detected`)

Known threat nodes: `Mixer_Contract`, `Smurf_1`, `Smurf_2`, `LayeringHub_A`

---

## Smart Contract

### `ZenithEscrow.sol`

**Key function:** `executeCrossBorderTransfer(receiver, a, b, c, publicInputs, tgnRiskScore, proofNonce, transferAmount)`

**Security features:**
- Replay protection via `bytes32` proof commitment mapping
- Checks-Effects-Interactions pattern (reentrancy safe)
- Manual reentrancy mutex (no OpenZeppelin dependency)
- Immutable verifier address (prevents governance attack)
- `DigitalComplianceCertificate` event as on-chain audit trail

### Events

```solidity
event DigitalComplianceCertificate(
    bytes32 indexed certificateId,
    address indexed sender,
    address indexed receiver,
    uint256 amount,
    uint8 tgnRiskScore,
    uint256 timestamp,
    bytes32 zkProofHash
);
```

---

## Docker

```bash
# Build
docker build -t zenith-middleware:2.0.0 .

# Run
docker run -p 8000:8000 \
  -e WEB3_RPC_URL=https://rpc.cardona.zkevm-rpc.com \
  -e CHAIN_ID=2442 \
  -e ZENITH_ESCROW_ADDRESS=0x... \
  -e ORACLE_PRIVATE_KEY=0x... \
  zenith-middleware:2.0.0
```

---

## Demo Results (Phase 2)

### Health Check
```json
{"status":"healthy","version":"2.0.0","chain_connected":true,"chain_id":2442,"tgn_threat_nodes":4}
```

### Clean Wallet Transaction (Wallet_A → Wallet_B)
```
Risk Score:    20/100 (LOW)
Anomaly Flags: STRUCTURING_PATTERN (amount near threshold 4999)
Status:        BLOCKCHAIN_ERROR (expected — Remix VM not reachable by web3.py)
```

### ZK Proof Generation (client_prover.js)
```
ZK Proof generated in 1082ms
Public signals: [123456000, 1000]
Protocol: groth16
Local proof verification: PASSED
TGN Risk Score: 20/100 → LOW
```

### Mixer Contract Detection (Wallet_A → Mixer_Contract)
```
Risk Score:    >85/100 (CRITICAL)
Status:        REJECTED_TGN
Anomaly Flags: DIRECT_MALICIOUS_NODE, PROXIMITY_ALERT
```

---

## Team

Built for **PidiHackathon** — Z.E.N.I.T.H. by Orion

---

## License

MIT License — see [LICENSE](LICENSE) for details.
