import asyncio
import logging
from web3 import Web3
from websockets import connect
from eth_typing import Address
from core.errors import SubmitError
from core.types import Network, VerificationData
from communication.messaging import send_messages
from sdk import get_payment_service_address
from communication.protocol import check_protocol_version

logger = logging.getLogger(__name__)

async def submit_multiple_and_wait_verification(
    batcher_url: str,
    eth_rpc_url: str,
    network: Network,
    verification_data: list[VerificationData],
    max_fees: list[int],
    wallet,  # Replace with the actual wallet instance for signing
    nonce: int
):
    await submit_multiple(batcher_url, network, verification_data, max_fees, wallet, nonce)

async def submit_multiple(
    batcher_url: str,
    network: Network,
    verification_data: list[VerificationData],
    max_fees: list[int],
    wallet,  # Replace with the actual wallet instance for signing
    nonce: int
):
    # Connect to the WebSocket
    async with connect(batcher_url) as websocket:
        logger.debug("WebSocket handshake has been successfully completed")
        
        # These should be the coroutine methods, not a function reference
        ws_write = websocket
        ws_read = websocket.recv

        await _submit_multiple(ws_write, ws_read, network, verification_data, max_fees, wallet, nonce)

async def _submit_multiple(
    ws_write, ws_read, network: Network,
    verification_data: list[VerificationData],
    max_fees: list[int], wallet, nonce: int
):
    await check_protocol_version(ws_read)

    if not verification_data:
        raise SubmitError.missing_required_parameter("verification_data")

    payment_service_addr = get_payment_service_address(network)
    await send_messages(
        ws_write, payment_service_addr,
        verification_data, max_fees, wallet, nonce
    )

async def submit_and_wait_verification(
    batcher_url: str,
    eth_rpc_url: str,
    network: Network,
    verification_data: VerificationData,
    max_fee: int,
    wallet,  # Replace with the actual wallet instance for signing
    nonce: int
):
    verification_data = [verification_data]
    max_fees = [max_fee]
    
    await submit_multiple_and_wait_verification(
        batcher_url, eth_rpc_url, network, verification_data, max_fees, wallet, nonce
    )

async def submit(
    batcher_url: str,
    network: Network,
    verification_data: VerificationData,
    max_fee: int,
    wallet,
    nonce: int
):
    verification_data = [verification_data]
    max_fees = [max_fee]
    
    await submit_multiple(batcher_url, network, verification_data, max_fees, wallet, nonce)
