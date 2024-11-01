import websockets
from .serialization import cbor_deserialize

EXPECTED_PROTOCOL_VERSION = 4

async def check_protocol_version(ws_read):
    try:
        async with websockets.connect(ws_read) as websocket:
            response = await websocket.recv()
            msg = cbor_deserialize(response)

            if isinstance(msg, dict) and 'ProtocolVersion' in msg:
                protocol_version = msg['ProtocolVersion']
                
                if protocol_version == EXPECTED_PROTOCOL_VERSION:
                    print("Protocol version matches.")
                else:
                    raise Exception(f"Protocol version mismatch: received {protocol_version}, expected {EXPECTED_PROTOCOL_VERSION}")
            else:
                raise Exception("Unexpected message format or missing 'ProtocolVersion' key")
    except Exception as e:
        print(f"Error: {e}")
