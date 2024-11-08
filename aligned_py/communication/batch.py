import asyncio
from logs import logs
from aligned_py.core.errors import SubmitError
from aligned_py.core.types import AlignedVerificationData, Network

RETRIES = 10
TIME_BETWEEN_RETRIES = 10  # seconds

async def await_batch_verification(
    aligned_verification_data: AlignedVerificationData,
    rpc_url: str,
    network: Network
) -> None:
    from aligned_py.sdk import is_proof_verified
    """Waits for the batch verification by retrying a fixed number of times with a delay between attempts."""
    for _ in range(RETRIES):
        verified = is_proof_verified(aligned_verification_data, network, rpc_url)
        if verified:
            return

        logs().debug(
            f"Proof not verified yet. Waiting {TIME_BETWEEN_RETRIES} seconds before checking again..."
        )
        await asyncio.sleep(TIME_BETWEEN_RETRIES)

    raise SubmitError.batch_verification_timeout(TIME_BETWEEN_RETRIES * RETRIES)
