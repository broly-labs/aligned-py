import cbor2

def cbor_serialize(value):
    return cbor2.dumps(value)

def cbor_deserialize(data):
    return cbor2.loads(data)