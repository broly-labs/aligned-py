import asyncio
import logging
from core.errors import SubmitError
from core.types import AlignedVerificationData, BatchInclusionData, Network, VerificationDataCommitment
from sdk import is_proof_verified

RETRIES = 10
TIME_BETWEEN_RETRIES = 10  # seconds

logger = logging.getLogger(__name__)

def handle_batch_inclusion_data(
    batch_inclusion_data: BatchInclusionData,
    aligned_verification_data: list,
    verification_data_commitments_rev: list
) -> None:
    """Handles the batch inclusion data by verifying and adding it to aligned_verification_data if valid."""
    logger.debug("Received response from batcher")
    logger.debug(f"Batch merkle root: {batch_inclusion_data.batch_merkle_root.hex()}")
    logger.debug(f"Index in batch: {batch_inclusion_data.index_in_batch}")

    if not verification_data_commitments_rev:
        raise SubmitError.empty_verification_data_commitments()

    verification_data_commitment = verification_data_commitments_rev.pop()

    if verify_response(verification_data_commitment, batch_inclusion_data):
        aligned_verification_data.append(
            AlignedVerificationData.new(verification_data_commitment, batch_inclusion_data)
        )

async def await_batch_verification(
    aligned_verification_data: AlignedVerificationData,
    rpc_url: str,
    network: Network
) -> None:
    """Waits for the batch verification by retrying a fixed number of times with a delay between attempts."""
    for _ in range(RETRIES):
        verified = await is_proof_verified(aligned_verification_data, network, rpc_url)
        if verified:
            return

        logger.debug(
            f"Proof not verified yet. Waiting {TIME_BETWEEN_RETRIES} seconds before checking again..."
        )
        await asyncio.sleep(TIME_BETWEEN_RETRIES)

    raise SubmitError.batch_verification_timeout(TIME_BETWEEN_RETRIES * RETRIES)

def verify_response(
    verification_data_commitment: VerificationDataCommitment,
    batch_inclusion_data: BatchInclusionData
) -> bool:
    """Verifies that the response data matches the sent proof data."""
    logger.debug("Verifying response data matches sent proof data...")

    batch_inclusion_proof = batch_inclusion_data.batch_inclusion_proof

    # The actual verification would depend on the `verify` method of the `MerkleProof`.
    # Here, we assume `batch_inclusion_proof.verify` method exists and matches the signature in Rust.
    if batch_inclusion_proof.verify(
        batch_inclusion_data.batch_merkle_root,
        batch_inclusion_data.index_in_batch,
        verification_data_commitment
    ):
        logger.debug("Done. Data sent matches batcher answer")
        return True

    logger.debug(
        "Verification data commitments and batcher response with merkle root %s and index in batch %s don't match",
        batch_inclusion_data.batch_merkle_root.hex(),
        batch_inclusion_data.index_in_batch
    )
    return False
