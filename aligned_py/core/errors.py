from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Union, Dict, Any
from eth_typing import Address
from aligned_py.core.types import ProofInvalidReason

class AlignedError(Exception):
    """Base exception class for all Aligned errors."""
    pass

class SubmitError(AlignedError):
    def __init__(self, error_type: str, details: Optional[Union[str, Dict[str, Any]]] = None):
        self.error_type = error_type
        self.details = details
        message = f"SubmitError({error_type})"
        if details:
            message += f": {details if isinstance(details, str) else str(details)}"
        super().__init__(message)

    @classmethod
    def web_socket_connection_error(cls, error: str) -> 'SubmitError':
        return cls("WebSocketConnectionError", error)

    @classmethod
    def web_socket_closed_unexpectedly(cls, close_frame: str) -> 'SubmitError':
        return cls("WebSocketClosedUnexpectedlyError", close_frame)

    @classmethod
    def io_error(cls, path: Path, error: str) -> 'SubmitError':
        return cls("IoError", {"path": str(path), "error": error})

    @classmethod
    def serialization_error(cls, error: str) -> 'SubmitError':
        return cls("SerializationError", error)

    @classmethod
    def ethereum_provider_error(cls, error: str) -> 'SubmitError':
        return cls("EthereumProviderError", error)

    @classmethod
    def hex_decoding_error(cls, error: str) -> 'SubmitError':
        return cls("HexDecodingError", error)

    @classmethod
    def wallet_signer_error(cls, error: str) -> 'SubmitError':
        return cls("WalletSignerError", error)

    @classmethod
    def missing_required_parameter(cls, param: str) -> 'SubmitError':
        return cls("MissingRequiredParameter", param)

    @classmethod
    def unsupported_proving_system(cls, system: str) -> 'SubmitError':
        return cls("UnsupportedProvingSystem", system)

    @classmethod
    def invalid_ethereum_address(cls, address: str) -> 'SubmitError':
        return cls("InvalidEthereumAddress", address)

    @classmethod
    def protocol_version_mismatch(cls, current: int, expected: int) -> 'SubmitError':
        return cls("ProtocolVersionMismatch", {"current": current, "expected": expected})

    @classmethod
    def batch_verified_event_stream_error(cls, error: str) -> 'SubmitError':
        return cls("BatchVerifiedEventStreamError", error)

    @classmethod
    def batch_verification_timeout(cls, timeout_seconds: int) -> 'SubmitError':
        return cls("BatchVerificationTimeout", {"timeout_seconds": timeout_seconds})

    @classmethod
    def no_response_from_batcher(cls) -> 'SubmitError':
        return cls("NoResponseFromBatcher")

    @classmethod
    def unexpected_batcher_response(cls, response: str) -> 'SubmitError':
        return cls("UnexpectedBatcherResponse", response)

    @classmethod
    def empty_verification_data_commitments(cls) -> 'SubmitError':
        return cls("EmptyVerificationDataCommitments")

    @classmethod
    def empty_verification_data_list(cls) -> 'SubmitError':
        return cls("EmptyVerificationDataList")

    @classmethod
    def invalid_nonce(cls) -> 'SubmitError':
        return cls("InvalidNonce")

    @classmethod
    def invalid_max_fee(cls) -> 'SubmitError':
        return cls("InvalidMaxFee")

    @classmethod
    def proof_queue_flushed(cls) -> 'SubmitError':
        return cls("ProofQueueFlushed")

    @classmethod
    def invalid_signature(cls) -> 'SubmitError':
        return cls("InvalidSignature")

    @classmethod
    def invalid_chain_id(cls) -> 'SubmitError':
        return cls("InvalidChainId")

    @classmethod
    def invalid_proof(cls, reason: ProofInvalidReason) -> 'SubmitError':
        return cls("InvalidProof", str(reason))

    @classmethod
    def proof_too_large(cls) -> 'SubmitError':
        return cls("ProofTooLarge")

    @classmethod
    def invalid_replacement_message(cls) -> 'SubmitError':
        return cls("InvalidReplacementMessage")

    @classmethod
    def insufficient_balance(cls) -> 'SubmitError':
        return cls("InsufficientBalance")

    @classmethod
    def invalid_payment_service_address(cls, received_addr: Address, expected_addr: Address) -> 'SubmitError':
        return cls("InvalidPaymentServiceAddress", {"received": received_addr, "expected": expected_addr})

    @classmethod
    def batch_submission_failed(cls, merkle_root: str) -> 'SubmitError':
        return cls("BatchSubmissionFailed", merkle_root)

    @classmethod
    def add_to_batch_error(cls) -> 'SubmitError':
        return cls("AddToBatchError")

    @classmethod
    def generic_error(cls, error: str) -> 'SubmitError':
        return cls("GenericError", error)

class VerificationError(AlignedError):
    def __init__(self, error_type: str, details: Any):
        self.error_type = error_type
        self.details = details
        super().__init__(f"VerificationError({error_type}): {details}")

    @classmethod
    def hex_decoding_error(cls, error: str) -> 'VerificationError':
        return cls("HexDecodingError", error)

    @classmethod
    def ethereum_provider_error(cls, error: str) -> 'VerificationError':
        return cls("EthereumProviderError", error)

    @classmethod
    def ethereum_call_error(cls, error: str) -> 'VerificationError':
        return cls("EthereumCallError", error)

    @classmethod
    def ethereum_not_a_contract(cls, address: Address) -> 'VerificationError':
        return cls("EthereumNotAContract", address)

class NonceError(AlignedError):
    def __init__(self, error_type: str, details: str):
        self.error_type = error_type
        self.details = details
        super().__init__(f"NonceError({error_type}): {details}")

    @classmethod
    def ethereum_provider_error(cls, error: str) -> 'NonceError':
        return cls("EthereumProviderError", error)

    @classmethod
    def ethereum_call_error(cls, error: str) -> 'NonceError':
        return cls("EthereumCallError", error)

class ChainIdError(AlignedError):
    def __init__(self, error_type: str, details: str):
        self.error_type = error_type
        self.details = details
        super().__init__(f"ChainIdError({error_type}): {details}")

    @classmethod
    def ethereum_provider_error(cls, error: str) -> 'ChainIdError':
        return cls("EthereumProviderError", error)

    @classmethod
    def ethereum_call_error(cls, error: str) -> 'ChainIdError':
        return cls("EthereumCallError", error)

class MaxFeeEstimateError(AlignedError):
    def __init__(self, error_type: str, details: str):
        self.error_type = error_type
        self.details = details
        super().__init__(f"MaxFeeEstimateError({error_type}): {details}")

    @classmethod
    def ethereum_provider_error(cls, error: str) -> 'MaxFeeEstimateError':
        return cls("EthereumProviderError", error)

    @classmethod
    def ethereum_gas_price_error(cls, error: str) -> 'MaxFeeEstimateError':
        return cls("EthereumGasPriceError", error)

class VerifySignatureError(AlignedError):
    def __init__(self, error_type: str, details: str):
        self.error_type = error_type
        self.details = details
        super().__init__(f"VerifySignatureError({error_type}): {details}")

    @classmethod
    def recover_typed_data_error(cls, error: str) -> 'VerifySignatureError':
        return cls("RecoverTypedDataError", error)

    @classmethod
    def encode_error(cls, error: str) -> 'VerifySignatureError':
        return cls("EncodeError", error)

class PaymentError(AlignedError):
    def __init__(self, error_type: str, details: Optional[str] = None):
        self.error_type = error_type
        self.details = details
        message = f"PaymentError({error_type})"
        if details:
            message += f": {details}"
        super().__init__(message)

    @classmethod
    def send_error(cls, error: str) -> 'PaymentError':
        return cls("SendError", error)

    @classmethod
    def submit_error(cls, error: str) -> 'PaymentError':
        return cls("SubmitError", error)

    @classmethod
    def payment_failed(cls) -> 'PaymentError':
        return cls("PaymentFailed")

class BalanceError(AlignedError):
    def __init__(self, error_type: str, details: str):
        self.error_type = error_type
        self.details = details
        super().__init__(f"BalanceError({error_type}): {details}")

    @classmethod
    def ethereum_provider_error(cls, error: str) -> 'BalanceError':
        return cls("EthereumProviderError", error)

    @classmethod
    def ethereum_call_error(cls, error: str) -> 'BalanceError':
        return cls("EthereumCallError", error)

class FileError(AlignedError):
    def __init__(self, error_type: str, details: Union[str, Dict[str, Any]]):
        self.error_type = error_type
        self.details = details
        super().__init__(f"FileError({error_type}): {details}")

    @classmethod
    def io_error(cls, path: Path, error: str) -> 'FileError':
        return cls("IoError", {"path": str(path), "error": error})

    @classmethod
    def serialization_error(cls, error: str) -> 'FileError':
        return cls("SerializationError", error)
