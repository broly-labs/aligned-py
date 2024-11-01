from web3 import Web3, HTTPProvider
from core.constants import (
    ADDITIONAL_SUBMISSION_GAS_COST_PER_PROOF,
    CONSTANT_GAS_COST,
    MAX_FEE_BATCH_PROOF_NUMBER,
    MAX_FEE_DEFAULT_PROOF_NUMBER
)
from core.errors import (
    NonceError,
    ChainIdError,
    BalanceError,
    MaxFeeEstimateError,
    PaymentError,
    VerificationError
)
from core.types import Network, PriceEstimate, AlignedVerificationData
from eth.batcher_payment_service import batcher_payment_service
from eth.aligned_service_manager import aligned_service_manager
from web3.contract import Contract
from eth_typing import Address
from typing import Any
import asyncio


# Network addresses dictionary equivalent to TypeScript's switch cases
NETWORK_ADDRESSES = {
    Network.Devnet: "0x7969c5eD335650692Bc04293B07F5BF2e7A673C0",
    Network.Holesky: "0x815aeCA64a974297942D2Bbf034ABEe22a38A003",
    Network.HoleskyStage: "0x7577Ec4ccC1E6C529162ec8019A49C13F6DAd98b"
}

def get_payment_service_address(network: Network) -> str:
    """Get the payment service address based on the network."""
    return NETWORK_ADDRESSES.get(network, "Invalid network")

def get_aligned_service_manager_address(network: Network) -> str:
    """Get the aligned service manager address based on the network."""
    addresses = {
        Network.Devnet: "0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8",
        Network.Holesky: "0x58F280BeBE9B34c9939C3C39e0890C81f163B623",
        Network.HoleskyStage: "0x9C5231FC88059C086Ea95712d105A2026048c39B"
    }
    return addresses.get(network, "Invalid network")

def get_next_nonce(eth_rpc_url: str, submitter_addr: str, network: Network) -> int:
    """Fetch the next nonce for the given address."""
    try:
        provider = Web3(HTTPProvider(eth_rpc_url))
        payment_service_address = get_payment_service_address(network)
        contract = batcher_payment_service(provider, payment_service_address)
        nonce = contract.functions.user_nonces(submitter_addr).call()
        return nonce
    except Exception as e:
        raise NonceError('EthereumCallError', str(e))

def get_chain_id(eth_rpc_url: str) -> int:
    """Fetch the chain ID from the provider."""
    try:
        provider = Web3(HTTPProvider(eth_rpc_url))
        chain_id = provider.eth.chain_id
        return chain_id
    except Exception as e:
        raise ChainIdError('EthereumCallError', str(e))

def get_balance_in_aligned(user: str, eth_rpc_url: str, network: Network) -> int:
    """Fetch the user's balance in aligned service."""
    try:
        provider = Web3(HTTPProvider(eth_rpc_url))
        payment_service_address = get_payment_service_address(network)
        
        # Call batcher_payment_service without await, since it's now synchronous
        contract = batcher_payment_service(provider, payment_service_address)
        
        # Call the contract's user_balances function without await
        balance = contract.functions.user_balances(user).call()
        return balance
    except Exception as e:
        raise BalanceError('EthereumCallError', str(e))

def compute_commitment(verification_key_bytes: bytes, proving_system: int) -> bytes:
    """Compute the commitment for verification key bytes."""
    data_to_hash = verification_key_bytes + proving_system.to_bytes(1, byteorder="big")
    return Web3.keccak(data_to_hash)

def fetch_gas_price(provider: Web3) -> int:
    """Fetch the current gas price."""
    try:
        gas_price = provider.eth.gas_price
        return gas_price
    except Exception as e:
        raise MaxFeeEstimateError('EthereumGasPriceError', str(e))

def fee_per_proof(eth_rpc_url: str, num_proofs_per_batch: int) -> int:
    """Calculate the fee per proof based on gas price and constants."""
    try:
        provider = Web3(HTTPProvider(eth_rpc_url))
        gas_price = fetch_gas_price(provider)
        
        estimated_gas_per_proof = (
            CONSTANT_GAS_COST + ADDITIONAL_SUBMISSION_GAS_COST_PER_PROOF * num_proofs_per_batch
        ) // num_proofs_per_batch
        return estimated_gas_per_proof * gas_price
    except Exception as e:
        raise MaxFeeEstimateError('EthereumProviderError', str(e))

def estimate_fee(eth_rpc_url: str, estimate: PriceEstimate) -> int:
    """Estimate fee based on the given price estimate type."""
    fee_per = fee_per_proof(eth_rpc_url, MAX_FEE_BATCH_PROOF_NUMBER)
    if estimate == PriceEstimate.Min:
        return fee_per
    elif estimate == PriceEstimate.Default:
        return fee_per * MAX_FEE_DEFAULT_PROOF_NUMBER
    elif estimate == PriceEstimate.Instant:
        return fee_per * MAX_FEE_BATCH_PROOF_NUMBER

def compute_max_fee(eth_rpc_url: str, num_proofs: int, num_proofs_per_batch: int) -> int:
    """Compute maximum fee based on proofs and batch size."""
    fee_per_proof_value = fee_per_proof(eth_rpc_url, num_proofs_per_batch)
    return fee_per_proof_value * num_proofs

def deposit_to_aligned(amount: int, signer, network: Network) -> dict:
    """Deposit an amount to the aligned service."""
    try:
        payment_service_address = get_payment_service_address(network)
        tx = signer.send_transaction({
            'to': payment_service_address,
            'value': amount
        })
        receipt = tx.wait_for_receipt()
        if not receipt:
            raise PaymentError('PaymentFailed')
        return receipt
    except Exception as e:
        raise PaymentError('SendError', str(e))


def is_proof_verified(
    aligned_verification_data: AlignedVerificationData,
    network: Network,
    eth_rpc_url: str
) -> bool:
    """
    Checks if the proof has been verified with Aligned and is included in the batch.

    Args:
        aligned_verification_data (AlignedVerificationData): The aligned verification data obtained when submitting the proofs.
        network (Network): The chain on which the verification will be done.
        eth_rpc_url (str): The URL of the Ethereum RPC node.

    Returns:
        bool: Indicates whether the proof was verified on-chain and is included in the batch.

    Raises:
        VerificationError: Various errors depending on the Ethereum connection, call errors, or decoding issues.
    """
    provider = Web3(Web3.HTTPProvider(eth_rpc_url))
    contract_address = get_aligned_service_manager_address(network)
    payment_service_addr = get_payment_service_address(network)

    service_manager = aligned_service_manager(provider, contract_address)

    # Concatenate all elements in the merkle proof
    merkle_proof = b''.join(aligned_verification_data.batch_inclusion_proof.path)
    verification_data_commitment = aligned_verification_data.verification_data_commitment

    try:
        # Call the verify_batch_inclusion method on the contract
        result = service_manager.functions.verify_batch_inclusion(
            verification_data_commitment.proof_commitment,
            verification_data_commitment.pub_input_commitment,
            verification_data_commitment.proving_system_aux_data_commitment,
            verification_data_commitment.proof_generator_addr,
            aligned_verification_data.batch_merkle_root,
            merkle_proof,
            aligned_verification_data.index_in_batch,
            payment_service_addr,
        ).call()
    except Exception as e:
        raise VerificationError.ethereum_call_error(f"Error during Ethereum call: {str(e)}")

    return result
