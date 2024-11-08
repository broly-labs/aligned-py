from enum import Enum, auto
from typing import TypeVar, Optional, List, Dict, Union, Any
from dataclasses import dataclass
import eth_account
from sha3 import keccak_256
import json

T = TypeVar('T')

class PriceEstimate(Enum):
    Min = auto()
    Default = auto()
    Instant = auto()

class ValidityResponseMessage(Enum):
    Valid = "Valid"
    InvalidNonce = "InvalidNonce"
    InvalidSignature = "InvalidSignature"
    InvalidChainId = "InvalidChainId"
    InvalidProof = "InvalidProof"
    InvalidMaxFee = "InvalidMaxFee"
    InvalidReplacementMessage = "InvalidReplacementMessage"
    AddToBatchError = "AddToBatchError"
    ProofTooLarge = "ProofTooLarge"
    InsufficientBalance = "InsufficientBalance"
    EthRpcError = "EthRpcError"
    InvalidPaymentServiceAddress = "InvalidPaymentServiceAddress"

class ProofInvalidReason(Enum):
    RejectedProof = "RejectedProof"
    VerifierNotSupported = "VerifierNotSupported"
    DisabledVerifier = "DisabledVerifier"

class Network(Enum):
    Devnet = "devnet"
    Holesky = "holesky"
    HoleskyStage = "holesky-stage"

class ProvingSystemId(Enum):
    GnarkPlonkBls12_381 = 0
    GnarkPlonkBn254 = 1
    Groth16Bn254 = 2
    SP1 = 3
    Risc0 = 4

    @classmethod
    def to_string(cls, id: int) -> str:
        try:
            return cls(id).name
        except ValueError:
            raise ValueError("Unsupported proof system ID")

@dataclass
class VerificationData:
    proving_system: ProvingSystemId
    proof: bytes
    public_input: Optional[bytes] = None
    verification_key: Optional[bytes] = None
    vm_program_code: Optional[bytes] = None
    proof_generator_address: str = ""

@dataclass
class VerificationDataCommitment:
    proof_commitment: bytes
    public_input_commitment: bytes
    proving_system_aux_data_commitment: bytes
    proof_generator_addr: bytes

    @classmethod
    def from_data(cls, data: VerificationData) -> 'VerificationDataCommitment':
        """Create VerificationDataCommitment from VerificationData"""
        if isinstance(data.proof, (list, tuple)):
            proof_bytes = bytes(data.proof)
        else:
            proof_bytes = data.proof if isinstance(data.proof, bytes) else bytes(data.proof)
        
        proof_commitment = keccak_256(proof_bytes).digest()

        public_input_commitment = bytes(32)
        if data.public_input is not None:
            input_bytes = bytes(data.public_input) if not isinstance(data.public_input, bytes) else data.public_input
            public_input_commitment = keccak_256(input_bytes).digest()

        proving_system_aux_data_commitment = bytes(32)
        proving_system_byte = bytes([data.proving_system.value])

        if data.vm_program_code is not None:
            program_bytes = bytes(data.vm_program_code) if not isinstance(data.vm_program_code, bytes) else data.vm_program_code
            hasher = keccak_256()
            hasher.update(program_bytes)
            hasher.update(proving_system_byte)
            proving_system_aux_data_commitment = hasher.digest()
        elif data.verification_key is not None:
            key_bytes = bytes(data.verification_key) if not isinstance(data.verification_key, bytes) else data.verification_key
            hasher = keccak_256()
            hasher.update(key_bytes)
            hasher.update(proving_system_byte)
            proving_system_aux_data_commitment = hasher.digest()

        if data.proof_generator_address.startswith('0x'):
            proof_generator_addr = bytes.fromhex(data.proof_generator_address[2:])
        else:
            proof_generator_addr = bytes.fromhex(data.proof_generator_address)

        return cls(
            proof_commitment=proof_commitment,
            public_input_commitment=public_input_commitment,
            proving_system_aux_data_commitment=proving_system_aux_data_commitment,
            proof_generator_addr=proof_generator_addr
        )

    def hash_data(self) -> bytes:
        """Hash the commitment data"""
        hasher = keccak_256()
        hasher.update(self.proof_commitment)
        hasher.update(self.public_input_commitment)
        hasher.update(self.proving_system_aux_data_commitment)
        hasher.update(self.proof_generator_addr)
        return hasher.digest()

class VerificationCommitmentBatch:
    @staticmethod
    def hash(data: VerificationDataCommitment) -> bytes:
        hasher = keccak_256()
        hasher.update(data.proof_commitment)
        hasher.update(data.public_input_commitment)
        hasher.update(data.proving_system_aux_data_commitment)
        hasher.update(data.proof_generator_addr)
        return hasher.digest()

    @staticmethod
    def hash_parent(child1: bytes, child2: bytes) -> bytes:
        hasher = keccak_256()
        hasher.update(child1)
        hasher.update(child2)
        return hasher.digest()

@dataclass
class Signature:
    r: bytes
    s: bytes
    v: int

@dataclass
class ClientMessage:
    verification_data: 'NoncedVerificationData'
    signature: Signature

    @classmethod
    def new(cls, verification_data: 'NoncedVerificationData', 
                         wallet: eth_account.Account) -> 'ClientMessage':
        # Create the typed data structure for EIP-712
        domain = {
            "name": "Aligned",
            "version": "1",
            "chainId": verification_data.chain_id,
            "verifyingContract": verification_data.payment_service_addr
        }

        types = {
            "NoncedVerificationData": [
                {"name": "verification_data_hash", "type": "bytes32"},
                {"name": "nonce", "type": "uint256"},
                {"name": "max_fee", "type": "uint256"}
            ]
        }

        # Get verification data hash
        verification_data_hash = VerificationCommitmentBatch.hash(
            VerificationDataCommitment.from_data(verification_data.verification_data)
        )

        # Create the value object
        value = {
            "verification_data_hash": verification_data_hash,
            "nonce": verification_data.nonce,
            "max_fee": verification_data.max_fee
        }

        # Sign using typed data (Note: this is a simplified version, actual EIP-712 signing would need more implementation)
        signed_message = eth_account.Account.sign_typed_data(wallet.key, domain, types, value)
        
        return cls(
            verification_data=verification_data,
            signature=Signature(
                r=signed_message.r,
                s=signed_message.s,
                v=signed_message.v
            )
        )

    def to_string(self) -> str:
        def format_big_int(value: int) -> str:
            if isinstance(value, str) and value.startswith('0x'):
                return value
            return f"0x{value:x}"

        payload = {
            "verification_data": {
                "verification_data": {
                    "proving_system": ProvingSystemId.to_string(
                        self.verification_data.verification_data.proving_system.value
                    ),
                    "proof": list(self.verification_data.verification_data.proof),
                    "pub_input": list(self.verification_data.verification_data.public_input) 
                        if self.verification_data.verification_data.public_input is not None 
                        else None,
                    "verification_key": list(self.verification_data.verification_data.verification_key)
                        if self.verification_data.verification_data.verification_key is not None
                        else None,
                    "vm_program_code": list(self.verification_data.verification_data.vm_program_code)
                        if self.verification_data.verification_data.vm_program_code is not None
                        else None,
                    "proof_generator_addr": self.verification_data.verification_data.proof_generator_address,
                },
                "nonce": format_big_int(self.verification_data.nonce),
                "max_fee": format_big_int(self.verification_data.max_fee),
                "chain_id": format_big_int(self.verification_data.chain_id),
                "payment_service_addr": self.verification_data.payment_service_addr,
            },
            "signature": {
                "r": hex(self.signature.r),
                "s": hex(self.signature.s),
                "v": self.signature.v,
            },
        }

        return json.dumps(payload)

@dataclass
class Proof:
    merkle_path: List[bytes]

@dataclass
class BatchInclusionData:
    batch_merkle_root: bytes
    batch_inclusion_proof: Proof
    index_in_batch: int

    @classmethod
    def new(cls, verification_data_batch_index: int, batch_merkle_tree: 'MerkleTree') -> 'BatchInclusionData':
        batch_inclusion_proof = batch_merkle_tree.get_proof_by_pos(verification_data_batch_index)
        
        if not batch_inclusion_proof:
            raise ValueError("Failed to get proof from merkle tree")

        return cls(
            batch_merkle_root=batch_merkle_tree.root,
            batch_inclusion_proof=batch_inclusion_proof,
            index_in_batch=verification_data_batch_index
        )

    def to_dict(self) -> dict:
        return {
            "batch_merkle_root": list(self.batch_merkle_root),
            "batch_inclusion_proof": {
                "merkle_path": [list(p) for p in self.batch_inclusion_proof.merkle_path]
            },
            "index_in_batch": self.index_in_batch
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'BatchInclusionData':
        return cls(
            batch_merkle_root=bytes(data["batch_merkle_root"]),
            batch_inclusion_proof=Proof(
                merkle_path=[bytes(p) for p in data["batch_inclusion_proof"]["merkle_path"]]
            ),
            index_in_batch=data["index_in_batch"]
        )

@dataclass
class AlignedVerificationData:
    verification_data_commitment: VerificationDataCommitment
    batch_merkle_root: bytes
    batch_inclusion_proof: Proof
    index_in_batch: int

    @classmethod
    def new(cls, 
            verification_data_commitment: VerificationDataCommitment,
            inclusion_data: BatchInclusionData) -> 'AlignedVerificationData':
        return cls(
            verification_data_commitment=verification_data_commitment,
            batch_merkle_root=inclusion_data.batch_merkle_root,
            batch_inclusion_proof=inclusion_data.batch_inclusion_proof,
            index_in_batch=inclusion_data.index_in_batch
        )

    def to_dict(self) -> dict:
        return {
            "verification_data_commitment": {
                "proof_commitment": list(self.verification_data_commitment.proof_commitment),
                "public_input_commitment": list(self.verification_data_commitment.public_input_commitment),
                "proving_system_aux_data_commitment": list(self.verification_data_commitment.proving_system_aux_data_commitment),
                "proof_generator_addr": list(self.verification_data_commitment.proof_generator_addr)
            },
            "batch_merkle_root": list(self.batch_merkle_root),
            "batch_inclusion_proof": {
                "merkle_path": [list(p) for p in self.batch_inclusion_proof.merkle_path]
            },
            "index_in_batch": self.index_in_batch
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'AlignedVerificationData':
        return cls(
            verification_data_commitment=VerificationDataCommitment(
                proof_commitment=bytes(data["verification_data_commitment"]["proof_commitment"]),
                public_input_commitment=bytes(data["verification_data_commitment"]["public_input_commitment"]),
                proving_system_aux_data_commitment=bytes(data["verification_data_commitment"]["proving_system_aux_data_commitment"]),
                proof_generator_addr=bytes(data["verification_data_commitment"]["proof_generator_addr"])
            ),
            batch_merkle_root=bytes(data["batch_merkle_root"]),
            batch_inclusion_proof=Proof(
                merkle_path=[bytes(p) for p in data["batch_inclusion_proof"]["merkle_path"]]
            ),
            index_in_batch=data["index_in_batch"]
        )

@dataclass
class NoncedVerificationData:
    verification_data: VerificationData
    nonce: Union[int, str]
    max_fee: Union[int, str]
    chain_id: Union[int, str]
    payment_service_addr: str

    NONCED_VERIFICATION_DATA_TYPE = "NoncedVerificationData(bytes32 verification_data_hash,uint256 nonce,uint256 max_fee)"

    def __post_init__(self):
        # Convert string inputs to integers if necessary
        if isinstance(self.nonce, str):
            self.nonce = int(self.nonce, 16) if self.nonce.startswith('0x') else int(self.nonce)
        if isinstance(self.max_fee, str):
            self.max_fee = int(self.max_fee, 16) if self.max_fee.startswith('0x') else int(self.max_fee)
        if isinstance(self.chain_id, str):
            self.chain_id = int(self.chain_id, 16) if self.chain_id.startswith('0x') else int(self.chain_id)

    @classmethod
    def new(cls,
            verification_data: VerificationData,
            nonce: Union[int, str],
            max_fee: Union[int, str],
            chain_id: Union[int, str],
            payment_service_addr: str) -> 'NoncedVerificationData':
        return cls(
            verification_data=verification_data,
            nonce=nonce,
            max_fee=max_fee,
            chain_id=chain_id,
            payment_service_addr=payment_service_addr
        )

    def get_domain(self) -> Dict:
        return {
            "name": "Aligned",
            "version": "1",
            "chainId": self.chain_id,
            "verifyingContract": self.payment_service_addr,
            "salt": None
        }

    def get_type_hash(self) -> bytes:
        return keccak_256(self.NONCED_VERIFICATION_DATA_TYPE.encode()).digest()

    def get_struct_hash(self) -> bytes:
        # Get verification data hash
        verification_data_hash = VerificationCommitmentBatch.hash(
            VerificationDataCommitment.from_data(self.verification_data)
        )
        
        # Get type hash
        type_hash = self.get_type_hash()
        
        # Convert nonce and max_fee to 32-byte big-endian representation
        nonce_bytes = self.nonce.to_bytes(32, byteorder='big')
        max_fee_bytes = self.max_fee.to_bytes(32, byteorder='big')
        
        # Hash according to EIP-712
        hasher = keccak_256()
        hasher.update(type_hash)
        hasher.update(verification_data_hash)
        hasher.update(nonce_bytes)
        hasher.update(max_fee_bytes)
        
        return hasher.digest()

    def to_dict(self) -> dict:
        return {
            "verification_data": {
                "proving_system": self.verification_data.proving_system.value,
                "proof": self.verification_data.proof,
                "public_input": self.verification_data.public_input,
                "verification_key": self.verification_data.verification_key,
                "vm_program_code": self.verification_data.vm_program_code,
                "proof_generator_address": self.verification_data.proof_generator_address
            },
            "nonce": hex(self.nonce) if isinstance(self.nonce, int) else self.nonce,
            "max_fee": hex(self.max_fee) if isinstance(self.max_fee, int) else self.max_fee,
            "chain_id": self.chain_id,
            "payment_service_addr": self.payment_service_addr
        }

class MerkleTree:
    def __init__(self, root: bytes):
        self.root = root
        self._leaves: List[bytes] = []

    def get_proof_by_pos(self, index: int) -> Optional[Proof]:
        if index >= len(self._leaves):
            return None
        
        merkle_path: List[bytes] = []
        current_index = index
        
        while current_index > 1:  # Continue until we reach the root
            is_right = current_index % 2 == 1
            sibling_index = current_index - 1 if is_right else current_index + 1
            
            if sibling_index < len(self._leaves):
                merkle_path.append(self._leaves[sibling_index])
            
            current_index = current_index // 2
        
        return Proof(merkle_path=merkle_path)

class ResponseMessage:
    @dataclass
    class BatchInclusionDataMessage:
        type: str = "BatchInclusionData"
        data: BatchInclusionData = None

    @dataclass
    class ProtocolVersionMessage:
        type: str = "ProtocolVersion"
        version: int = None

    @dataclass
    class CreateNewTaskErrorMessage:
        type: str = "CreateNewTaskError"
        error: str = None

    @dataclass
    class InvalidProofMessage:
        type: str = "InvalidProof"
        reason: ProofInvalidReason = None

    @dataclass
    class BatchResetMessage:
        type: str = "BatchReset"

    @dataclass
    class ErrorMessage:
        type: str = "Error"
        message: str = None

    @staticmethod
    def batch_inclusion_data(data: BatchInclusionData) -> 'ResponseMessage.BatchInclusionDataMessage':
        return ResponseMessage.BatchInclusionDataMessage(data=data)

    @staticmethod
    def protocol_version(version: int) -> 'ResponseMessage.ProtocolVersionMessage':
        return ResponseMessage.ProtocolVersionMessage(version=version)

    @staticmethod
    def create_new_task_error(error: str) -> 'ResponseMessage.CreateNewTaskErrorMessage':
        return ResponseMessage.CreateNewTaskErrorMessage(error=error)

    @staticmethod
    def invalid_proof(reason: ProofInvalidReason) -> 'ResponseMessage.InvalidProofMessage':
        return ResponseMessage.InvalidProofMessage(reason=reason)

    @staticmethod
    def batch_reset() -> 'ResponseMessage.BatchResetMessage':
        return ResponseMessage.BatchResetMessage()

    @staticmethod
    def error(message: str) -> 'ResponseMessage.ErrorMessage':
        return ResponseMessage.ErrorMessage(message=message)

ResponseMessageType = Union[
    ResponseMessage.BatchInclusionDataMessage,
    ResponseMessage.ProtocolVersionMessage,
    ResponseMessage.CreateNewTaskErrorMessage,
    ResponseMessage.InvalidProofMessage,
    ResponseMessage.BatchResetMessage,
    ResponseMessage.ErrorMessage
]

def is_batch_inclusion_data(data: Any) -> bool:
    """Type guard for BatchInclusionData"""
    return (
        isinstance(data, BatchInclusionData) and
        isinstance(data.batch_merkle_root, bytes) and
        isinstance(data.index_in_batch, int) and
        isinstance(data.batch_inclusion_proof, Proof) and
        isinstance(data.batch_inclusion_proof.merkle_path, list) and
        all(isinstance(x, bytes) for x in data.batch_inclusion_proof.merkle_path)
    )

def is_aligned_verification_data(data: Any) -> bool:
    """Type guard for AlignedVerificationData"""
    return (
        isinstance(data, AlignedVerificationData) and
        isinstance(data.verification_data_commitment, VerificationDataCommitment) and
        isinstance(data.batch_merkle_root, bytes) and
        isinstance(data.index_in_batch, int) and
        isinstance(data.batch_inclusion_proof, Proof) and
        isinstance(data.batch_inclusion_proof.merkle_path, list) and
        all(isinstance(x, bytes) for x in data.batch_inclusion_proof.merkle_path)
    )

class ProtocolVersion:
    @staticmethod
    def from_bytes_buffer(buffer: bytes) -> int:
        """Convert bytes to protocol version number"""
        return int.from_bytes(buffer[:2], byteorder='big')
