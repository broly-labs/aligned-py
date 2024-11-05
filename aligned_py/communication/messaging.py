from typing import List
from eth_typing import Address
from eth_account import Account
from core.errors import SubmitError
from core.types import (
    AlignedVerificationData, ClientMessage, NoncedVerificationData, BatchInclusionData,
    ValidityResponseMessage, VerificationData, VerificationDataCommitment
)
from communication.serialization import cbor_serialize, cbor_deserialize
import json
import websockets

RETRIES = 10
TIME_BETWEEN_RETRIES = 10  # seconds

async def send_messages(
    socket, payment_service_addr: Address,
    verification_data: List[VerificationData], max_fees: List[int],
    wallet: Account, nonce: int
) -> List[NoncedVerificationData]:
    """Send a series of messages and process responses."""
    sent_verification_data = []
    chain_id = 17000  # Set this according to your setup

    for idx, data in enumerate(verification_data):
        nonced_data = NoncedVerificationData.new(
            verification_data=data,
            nonce=nonce,
            max_fee=max_fees[idx],
            chain_id=chain_id,
            payment_service_addr=payment_service_addr
        )
        nonce += 1

        client_msg = ClientMessage.new(nonced_data, wallet)
        msg_bin = cbor_serialize(json.loads(client_msg.to_string()))
        await socket.send(msg_bin)
        print("Message sent...")

        async for message in socket:
            response_msg = cbor_deserialize(message)

            if response_msg == ValidityResponseMessage.Valid.value:
                break
            else:
                handle_response_error(response_msg)

    sent_verification_data.append(nonced_data)

    return sent_verification_data


async def receive(
    socket, total_messages: int, num_responses: List[int],
    verification_data_commitments_rev: List[VerificationDataCommitment]
) -> List[AlignedVerificationData]:
    """Receive messages and process each response."""
    aligned_verification_data = []

    try:
        async for message in socket:
            num_responses += 1
            response_msg = cbor_deserialize(message)

            if next(iter(response_msg.keys())) == "BatchInclusionData":
                inclusion_data = BatchInclusionData(
                    batch_merkle_root=response_msg.get("BatchInclusionData").get("batch_merkle_root"),
                    batch_inclusion_proof=response_msg.get("BatchInclusionData").get("batch_inclusion_proof"),
                    index_in_batch=response_msg.get("BatchInclusionData").get("index_in_batch")
                )

                aligned_verification_data.append(
                    AlignedVerificationData.new(
                        verification_data_commitment=verification_data_commitments_rev,
                        inclusion_data=inclusion_data
                    )
                )
                
                if num_responses >= total_messages:
                    break
    except websockets.ConnectionClosed:
        print("WebSocket connection closed.")

    return aligned_verification_data

def handle_response_error(response_msg):
    """Handles errors based on the validity response message."""
    if response_msg == ValidityResponseMessage.InvalidSignature.value:
        raise SubmitError.invalid_signature()
    elif response_msg == ValidityResponseMessage.InvalidNonce.value:
        raise SubmitError.invalid_nonce()
    elif response_msg == ValidityResponseMessage.ProofTooLarge.value:
        raise SubmitError.proof_too_large()
    elif response_msg == ValidityResponseMessage.InvalidProof.value:
        raise SubmitError.invalid_proof(response_msg.reason)
    elif response_msg == ValidityResponseMessage.InvalidMaxFee.value:
        raise SubmitError.invalid_max_fee()
    elif response_msg == ValidityResponseMessage.InsufficientBalance.value:
        raise SubmitError.insufficient_balance(response_msg.address)
    elif response_msg == ValidityResponseMessage.InvalidChainId.value:
        raise SubmitError.invalid_chain_id()
    elif response_msg == ValidityResponseMessage.InvalidReplacementMessage.value:
        raise SubmitError.invalid_replacement_message()
    elif response_msg == ValidityResponseMessage.AddToBatchError.value:
        raise SubmitError.add_to_batch_error()
    elif response_msg == ValidityResponseMessage.EthRpcError.value:
        raise SubmitError.ethereum_provider_error("Batcher experienced Eth RPC connection error")
    elif response_msg == ValidityResponseMessage.InvalidPaymentServiceAddress.value:
        raise SubmitError.invalid_payment_service_address(response_msg.received_addr, response_msg.expected_addr)

