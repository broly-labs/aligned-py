from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, List, Union, Dict, Any
from eth_typing import Address, HexStr
from eth_utils import keccak, to_bytes, hexstr_if_str
from dataclasses import asdict
from eth_account import Account
import json
from communication.protocol import check_protocol_version
from hashlib import sha3_256

NONCED_VERIFICATION_DATA_TYPE = b"NoncedVerificationData(bytes32 verification_data_hash,uint256 nonce,uint256 max_fee)"

def keccak256(data: bytes) -> bytes:
    hasher = sha3_256()
    hasher.update(data)
    return hasher.digest()

class ProvingSystemId(Enum):
    GnarkPlonkBls12_381 = 0 
    GnarkPlonkBn254 = 1
    Groth16Bn254 = 2
    SP1 = 3
    Risc0 = 4

    def __str__(self):
        return self.name

@dataclass
class VerificationData:
    proving_system: ProvingSystemId
    proof: Union[bytes, List[int]]
    proof_generator_addr: Union[str, bytes, Address]
    pub_input: Optional[Union[bytes, List[int]]] = None
    verification_key: Optional[Union[bytes, List[int]]] = None
    vm_program_code: Optional[Union[bytes, List[int]]] = None

    def to_dict(self):
        data = asdict(self)
        data['proving_system'] = self.proving_system.name
        return data

@dataclass
class NoncedVerificationData:
    verification_data: VerificationData
    nonce: int
    max_fee: int
    chain_id: int
    payment_service_addr: Address

    @classmethod
    def new(cls, verification_data: VerificationData, nonce: int, max_fee: int, chain_id: int, payment_service_addr: Address) -> 'NoncedVerificationData':
        return cls(
            verification_data=verification_data,
            nonce=nonce,
            max_fee=max_fee,
            chain_id=chain_id,
            payment_service_addr=payment_service_addr
        )
    
    def to_dict(self):
        return {
            "verification_data": self.verification_data.to_dict(),  # Ensure VerificationData uses to_dict
            "nonce": self.nonce,
            "max_fee": self.max_fee,
            "chain_id": self.chain_id,
            "payment_service_addr": self.payment_service_addr
        }

class PriceEstimate(Enum):
    Min = 0
    Default = 1
    Instant = 2

@dataclass
class VerificationDataCommitment:
    proof_commitment: bytes
    pub_input_commitment: bytes
    proving_system_aux_data_commitment: bytes
    proof_generator_addr: bytes

    @classmethod
    def from_verification_data(cls, verification_data: VerificationData) -> 'VerificationDataCommitment':
        # Convert list to bytes if necessary
        def to_bytes(data: Union[bytes, List[int]]) -> bytes:
            return bytes(data) if isinstance(data, list) else data

        # Hash proof
        proof_commitment = keccak256(to_bytes(verification_data.proof))

        # Hash pub_input if it exists, otherwise default to 32 zero bytes
        pub_input_commitment = keccak256(to_bytes(verification_data.pub_input or [0] * 32))

        # Use proving system byte and hash either verification_key or vm_program_code
        proving_system_byte = verification_data.proving_system.value.to_bytes(1, 'big')
        if verification_data.vm_program_code is not None:
            vm_code = to_bytes(verification_data.vm_program_code)
            proving_system_aux_data_commitment = keccak256(vm_code + proving_system_byte)
        elif verification_data.verification_key is not None:
            vk = to_bytes(verification_data.verification_key)
            proving_system_aux_data_commitment = keccak256(vk + proving_system_byte)
        else:
            proving_system_aux_data_commitment = bytes([0] * 32)

        # Convert address to bytes
        proof_generator_addr = bytes.fromhex(verification_data.proof_generator_addr[2:])

        return cls(
            proof_commitment=proof_commitment,
            pub_input_commitment=pub_input_commitment,
            proving_system_aux_data_commitment=proving_system_aux_data_commitment,
            proof_generator_addr=proof_generator_addr
        )
@dataclass
class MerkleProof:
    path: List[bytes]
    indices: List[int]

@dataclass
class BatchInclusionData:
    batch_merkle_root: bytes
    batch_inclusion_proof: MerkleProof
    index_in_batch: int

    @classmethod
    def new(cls, verification_data_batch_index: int, batch_merkle_tree: 'MerkleTree') -> 'BatchInclusionData':
        batch_inclusion_proof = batch_merkle_tree.get_proof_by_pos(verification_data_batch_index)
        return cls(
            batch_merkle_root=batch_merkle_tree.root,
            batch_inclusion_proof=batch_inclusion_proof,
            index_in_batch=verification_data_batch_index
        )

from dataclasses import asdict
@dataclass
class ClientMessage:
    verification_data: NoncedVerificationData
    signature: bytes

    @classmethod
    async def new(cls, verification_data: NoncedVerificationData, wallet) -> 'ClientMessage':
        domain_data = {
            'name': 'Aligned',
            'version': '1',
            'chainId': verification_data.chain_id,
            'verifyingContract': verification_data.payment_service_addr,
            # 'salt': None
        }

        commitment = VerificationDataCommitment.from_verification_data(verification_data.verification_data)
        verifi_data = keccak(commitment.proof_commitment +
                        commitment.pub_input_commitment +
                        commitment.proving_system_aux_data_commitment +
                        commitment.proof_generator_addr)
        message = {
            'verification_data_hash': verifi_data,
            'nonce': verification_data.nonce,
            'max_fee': verification_data.max_fee
        }
        
        msg_types = {
            "NoncedVerificationData": [
                {"name": "verification_data_hash", "type": "bytes32"},
                {"name": "nonce", "type": "uint256"},
                {"name": "max_fee", "type": "uint256"}
            ]
        }

        await check_protocol_version("wss://batcher.alignedlayer.com")
        signed_data = Account.sign_typed_data(wallet.key, domain_data, msg_types, message)
        
        return cls(verification_data=verification_data, signature=signed_data.signature)

    def to_dict(self):
        return {
            "verification_data": self.verification_data.to_dict(),
            "signature": self.signature.hex()
        }

@dataclass
class AlignedVerificationData:
    verification_data_commitment: VerificationDataCommitment
    batch_merkle_root: bytes
    batch_inclusion_proof: MerkleProof
    index_in_batch: int

    @classmethod
    def new(cls, verification_data_commitment: VerificationDataCommitment, inclusion_data: BatchInclusionData) -> 'AlignedVerificationData':
        return cls(
            verification_data_commitment=verification_data_commitment,
            batch_merkle_root=inclusion_data.batch_merkle_root,
            batch_inclusion_proof=inclusion_data.batch_inclusion_proof,
            index_in_batch=inclusion_data.index_in_batch
        )

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

    def __str__(self):
        return self.value

class ProofInvalidReason(Enum):
    RejectedProof = "RejectedProof"
    VerifierNotSupported = "VerifierNotSupported"
    DisabledVerifier = "DisabledVerifier"

    def __str__(self):
        return self.value

class Network(Enum):
    Devnet = "devnet"
    Holesky = "holesky"
    HoleskyStage = "holesky-stage"

    @classmethod
    def from_str(cls, s: str) -> 'Network':
        s = s.lower()
        if s == "holesky":
            return cls.Holesky
        elif s == "holesky-stage":
            return cls.HoleskyStage
        elif s == "devnet":
            return cls.Devnet
        raise ValueError('Invalid network, possible values are: "holesky", "holesky-stage", "devnet"')

@dataclass
class ResponseStreamError:
    code: int
    reason: Optional[str] = None

class ResponseMessage:
    def __init__(
        self,
        message_type: str,
        batch_inclusion_data: Optional[BatchInclusionData] = None,
        protocol_version: Optional[int] = None,
        error_message: Optional[str] = None,
        create_new_task_error: Optional[str] = None,
        invalid_proof: Optional[ProofInvalidReason] = None,
        batch_reset: bool = False
    ):
        self.type = message_type
        self.data = batch_inclusion_data
        self.version = protocol_version
        self.message = error_message
        self.create_new_task_error = create_new_task_error
        self.invalid_proof = invalid_proof
        self.batch_reset = batch_reset

    @classmethod
    def create_batch_inclusion_data(cls, data: BatchInclusionData) -> 'ResponseMessage':
        return cls("BatchInclusionData", batch_inclusion_data=data)

    @classmethod
    def create_protocol_version(cls, version: int) -> 'ResponseMessage':
        return cls("ProtocolVersion", protocol_version=version)

    @classmethod
    def create_error(cls, message: str) -> 'ResponseMessage':
        return cls("Error", error_message=message)

    @classmethod
    def create_new_task_error(cls, error: str) -> 'ResponseMessage':
        return cls("CreateNewTaskError", create_new_task_error=error)

    @classmethod
    def create_invalid_proof(cls, reason: ProofInvalidReason) -> 'ResponseMessage':
        return cls("InvalidProof", invalid_proof=reason)

    @classmethod
    def create_batch_reset(cls) -> 'ResponseMessage':
        return cls("BatchReset", batch_reset=True)

    def to_dict(self) -> Dict[str, Any]:
        result = {"type": self.type}
        if self.data:
            result["data"] = asdict(self.data)
        if self.version is not None:
            result["version"] = self.version
        if self.message:
            result["message"] = self.message
        if self.create_new_task_error:
            result["create_new_task_error"] = self.create_new_task_error
        if self.invalid_proof:
            result["invalid_proof"] = self.invalid_proof.value
        if self.batch_reset:
            result["batch_reset"] = True
        return result

    def __str__(self) -> str:
        return json.dumps(self.to_dict())
    