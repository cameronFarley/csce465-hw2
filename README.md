# CSCE 465 Homework 2

Protect agent messages with classic cryptography.

## Files

| File | Task |
|---|---|
| `baseline_ctr.py` | Task 1: AES-CTR without a MAC, bit-flip and replay demo |
| `handshake.py` | Task 2: authenticated Diffie-Hellman handshake |
| `secure_record.py` | Task 3: encrypt-then-MAC record layer |
| `tests/` | Task 4: adversarial tests |
| `ffdhe3072.pem` | Diffie-Hellman group file used by Task 2 |
| `report.pdf` | Report |
| `AI_USAGE.md` | AI usage record |

## Setup

Requires Python 3 and OpenSSL 3.0 or newer.

```
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

`ffdhe3072.pem` is included. To regenerate it:

```
cd "$HOME/csce465-agentsec/hw2"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

## Run

From the `hw2/` directory with the venv active:

```
python baseline_ctr.py
python handshake.py
python secure_record.py
```

Each script prints its own demo output.

## Tests

From the `hw2/` directory:

```
python -m pytest -v
```

All 31 tests should pass.
