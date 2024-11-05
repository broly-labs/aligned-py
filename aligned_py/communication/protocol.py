import websockets
from .serialization import cbor_deserialize
from core.errors import SubmitError

EXPECTED_PROTOCOL_VERSION = 4

async def check_protocol_version(ws_read):
    try:
        async with websockets.connect(ws_read) as websocket:
            response = await websocket.recv()
            msg = cbor_deserialize(response)

            if isinstance(msg, dict) and 'ProtocolVersion' in msg:
                protocol_version = msg['ProtocolVersion']

                # Compare the received protocol version with the expected one
                if protocol_version > EXPECTED_PROTOCOL_VERSION:
                    raise ProtocolVersionMismatch(current=protocol_version, expected=EXPECTED_PROTOCOL_VERSION)
            else:
                raise UnexpectedBatcherResponse()
                
    except websockets.ConnectionClosed:
        raise SubmitError.generic_error("WebSocket connection closed unexpectedly.")
    except Exception as e:
        # Catch any unexpected errors and wrap them in a SubmitError
        raise SubmitError.generic_error(f"Unexpected error: {str(e)}")

class ProtocolVersionMismatch(SubmitError):
    def __init__(self, current, expected):
        self.current = current
        self.expected = expected
        super().__init__(f"Protocol version mismatch: received {current}, expected {expected}")

class UnexpectedBatcherResponse(SubmitError):
    def __init__(self, message="Batcher did not respond with the protocol version"):
        self.message = message
        super().__init__(message)
