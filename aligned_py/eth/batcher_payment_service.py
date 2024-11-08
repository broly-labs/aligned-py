import json
from web3 import Web3
from pathlib import Path

# Load the ABI for BatcherPaymentService
with open(Path(__file__).parent / '../../abi/BatcherPaymentService.json') as f:
    BatcherPaymentServiceABI = json.load(f)

def batcher_payment_service(provider: Web3, contract_address: str):
    """Creates an instance of the BatcherPaymentService contract."""
    code = provider.eth.get_code(contract_address)
    if code == b'':
        raise Exception(f'EthereumNotAContract: No contract found at address {contract_address}')
    
    contract = provider.eth.contract(address=contract_address, abi=BatcherPaymentServiceABI['abi'])
    return contract
