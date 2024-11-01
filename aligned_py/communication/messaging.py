import asyncio
import logging
from typing import List, Union
from eth_typing import Address
from web3 import Web3
from core.errors import SubmitError
from core.types import (
    AlignedVerificationData, ClientMessage, NoncedVerificationData,
    ResponseMessage, ValidityResponseMessage, VerificationData, VerificationDataCommitment
)
from communication.batch import handle_batch_inclusion_data
from communication.serialization import cbor_serialize, cbor_deserialize
import cbor2
from sdk import is_proof_verified
import json
from websockets import WebSocketClientProtocol
from collections import deque
from websockets import connect

logger = logging.getLogger(__name__)

RETRIES = 10
TIME_BETWEEN_RETRIES = 10  # seconds

async def send_messages(
    # response_stream, 
    ws_write, payment_service_addr: Address,
    verification_data: List[VerificationData], max_fees: List[int],
    wallet, nonce: int
) -> List[NoncedVerificationData]:
    """Send a series of messages and process responses."""
    sent_verification_data = []
    chain_id = 17000

    async with connect("wss://batcher.alignedlayer.com") as websocket:
        for idx, data in enumerate(verification_data):
            nonced_data = NoncedVerificationData.new(
                data, nonce, max_fees[idx], chain_id, payment_service_addr
            )
            nonce += 1

            msg = await ClientMessage.new(nonced_data, wallet)
            msg_dict = msg.to_dict()
            msg_bin = cbor_serialize(msg_dict)
            array_of_numbers = list(msg_bin[:100])

            print(array_of_numbers)

            await websocket.send(msg_bin)

            response_bin = await websocket.recv()

            # Deserialize the response from CBOR format
            response = cbor_deserialize(response_bin)
            print(response)

            # try:
            #     msg = await response_stream.__anext__()
            # except StopAsyncIteration:
            #     raise SubmitError.generic_error(
            #         "Connection was closed without close message before receiving all messages"
            #     )

            # response_msg: ValidityResponseMessage = cbor_deserialize(msg)

            # if response_msg == ValidityResponseMessage.Valid:
            #     logger.debug("Message was valid")
            # else:
            #     handle_response_error(response_msg)

            # sent_verification_data.append(nonced_data)

    return sent_verification_data


async def receive(
    ws_read, ws_write, total_messages: int,
    num_responses: list,  # Ensure this is a list to allow modifications
    verification_data_commitments_rev: list
) -> list:
    """Receive messages and process each response."""
    aligned_verification_data = []

    while num_responses[0] < total_messages:
        raw_msg = await ws_read()

        # Attempt CBOR decoding directly instead of UTF-8
        try:
            msg = cbor2.loads(raw_msg)  # Use CBOR to decode binary data
        except cbor2.CBORDecodeError:
            raise SubmitError.generic_error("Failed to decode message as CBOR")

        await process_batch_inclusion_data(
            msg, aligned_verification_data, verification_data_commitments_rev, num_responses
        )

        if num_responses[0] == total_messages:
            await ws_write.close()
            return aligned_verification_data

    raise SubmitError.generic_error("Connection closed without receiving all expected messages")

async def process_batch_inclusion_data(
    msg, aligned_verification_data: list,
    verification_data_commitments_rev: list,
    num_responses: list  # List used to allow modification by reference
) -> None:
    """Process batch inclusion data and update the count of responses."""
    
    # Increment num_responses by modifying the first element in the list
    num_responses[0] += 1

    data = msg

    # Decode the message to check response type
    if isinstance(msg, ResponseMessage.BatchInclusionData):
        handle_batch_inclusion_data(msg, aligned_verification_data, verification_data_commitments_rev)
    elif isinstance(msg, ResponseMessage.ProtocolVersion):
        raise SubmitError.unexpected_batcher_response("Received protocol version instead of batch inclusion data")
    elif isinstance(msg, ResponseMessage.BatchReset):
        raise SubmitError.proof_queue_flushed("Proof queue was flushed by the batcher")
    elif isinstance(msg, ResponseMessage.Error):
        print(f"Error from batcher: {msg}")
    elif isinstance(msg, ResponseMessage.CreateNewTaskError):
        raise SubmitError.batch_submission_failed(f"Could not create task with merkle root {msg}")
    elif isinstance(msg, ResponseMessage.InvalidProof):
        raise SubmitError.invalid_proof(msg)
    else:
        raise SubmitError.serialization_error("Unknown message type received")

async def handle_batch_inclusion_data(
    batch_inclusion_data,
    aligned_verification_data: List[AlignedVerificationData],
    verification_data_commitments_rev: deque[VerificationDataCommitment]
):
    """Handle batch inclusion data and append to aligned verification data."""
    # Process and align verification data as needed
    aligned_verification_data.append(batch_inclusion_data)

def handle_response_error(response_msg: ValidityResponseMessage) -> None:
    """Handles errors based on the validity response message."""
    if response_msg == ValidityResponseMessage.InvalidNonce:
        raise SubmitError.invalid_nonce()
    elif response_msg == ValidityResponseMessage.InvalidSignature:
        raise SubmitError.invalid_signature()
    elif response_msg == ValidityResponseMessage.ProofTooLarge:
        raise SubmitError.proof_too_large()
    elif response_msg == ValidityResponseMessage.InvalidProof:
        raise SubmitError.invalid_proof(response_msg.reason)
    elif response_msg == ValidityResponseMessage.InvalidMaxFee:
        raise SubmitError.invalid_max_fee()
    elif response_msg == ValidityResponseMessage.InsufficientBalance:
        raise SubmitError.insufficient_balance(response_msg.address)
    elif response_msg == ValidityResponseMessage.InvalidChainId:
        raise SubmitError.invalid_chain_id()
    elif response_msg == ValidityResponseMessage.InvalidReplacementMessage:
        raise SubmitError.invalid_replacement_message()
    elif response_msg == ValidityResponseMessage.AddToBatchError:
        raise SubmitError.add_to_batch_error()
    elif response_msg == ValidityResponseMessage.EthRpcError:
        raise SubmitError.ethereum_provider_error("Batcher experienced Eth RPC connection error")
    elif response_msg == ValidityResponseMessage.InvalidPaymentServiceAddress:
        raise SubmitError.invalid_payment_service_address(response_msg.received_addr, response_msg.expected_addr)
    else:
        raise SubmitError.generic_error("Unknown validity response message")
