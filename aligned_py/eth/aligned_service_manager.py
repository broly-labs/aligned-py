import json
from web3 import Web3
from pathlib import Path

# Load the ABI for AlignedLayerServiceManager
with open(Path(__file__).parent / '../abi/AlignedLayerServiceManager.json') as f:
    AlignedLayerServiceManagerABI = json.load(f)

def aligned_service_manager(provider: Web3, contract_address: str):
    """Creates an instance of the AlignedLayerServiceManager contract."""
    # Verify the contract code exists at the address
    code = provider.eth.get_code(contract_address)
    if code == b'':  # In web3.py, an empty contract returns an empty bytes object
        raise Exception(f'EthereumNotAContract: No contract found at address {contract_address}')
    
    # Create the contract instance
    contract = provider.eth.contract(address=contract_address, abi=AlignedLayerServiceManagerABI['abi'])
    return contract
