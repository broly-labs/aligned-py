# Aligned-PY

Aligned-PY is a Python library for interacting with the Aligned layer.

## SDK API Reference

### submit

Submits a proof to the batcher to be verified and returns an aligned verification data struct.

```py
from aligned_py.sdk import submit, Network

async def main():
    result = await submit(
        "BATCHER_URL",
        "NETWORK.NAME",
        "VerificationData",
        "MAX_FEE",
        "WALLET_ACCOUNT",
        "NONCE"
    )
    print(result)
```

### submit_multiple

Submits multiple proofs to the batcher to be verified and returns an aligned verification data array.

```py
from aligned_py.sdk import submit_multiple, Network

async def main():
    result = await submit_multiple(
        "BATCHER_URL",
        "NETWORK.NAME",
        "List[VerificationData]",
        "MAX_FEE",
        "WALLET_ACCOUNT",
        "NONCE"
    )
    print(result)
```

### submit_and_wait_verification

Submits a proof to the batcher to be verified, waits for the verification on ethereum and returns an aligned verification data struct.

```py
from aligned_py.sdk import submit_and_wait_verification, Network
    
async def main():
    result = await submit_multiple(
        "BATCHER_URL",
        "ETH_RPC_URL",
        "NETWORK.NAME",
        "VerificationData",
        "MAX_FEE",
        "WALLET_ACCOUNT",
        "NONCE"
    )
    print(result)
```

### is_proof_verified

Checks if the proof has been verified with Aligned and is included in the batch on-chain.

```py
from aligned_py.sdk import is_proof_verified, Network

def main():    
    verified = is_proof_verified(
        "AlignedVerificationData",
        "NETWORK.NAME",
        "ETH_RPC_URL"
    )
    print(verified)
```

### get_next_nonce

Returns the nonce to use for a given address.

```py
from aligned_py.sdk import get_next_nonce, Network

def main():    
    nonce = get_next_nonce(
        "ETH_RPC_URL",
        "ADDRESS",
        "NETWORK.NAME"
    )
    print(nonce)
```

### get_balance_in_aligned

Queries a User's balance that was deposited in Aligned

```py
from aligned_py.sdk import get_next_nonce, Network

def main():    
    nonce = get_next_nonce(
        "ETH_RPC_URL",
        "ADDRESS",
        "NETWORK.NAME"
    )
    print(nonce)
```

