import hashlib

class FakeIPFS:
    def __init__(self):
        self.datastore = {}

    def add(self, data: bytes) -> str:
        """Adds data to the fake IPFS and returns a CID (Content IDentifier)."""
        # Compute a simple CID using SHA256. This isn't the real algorithm IPFS uses, but it'll work for our mock version.
        if isinstance(data, str):
            data = data.encode()
            
        cid = hashlib.sha256(data).hexdigest()
        self.datastore[cid] = data
        return cid

    def cat(self, cid: str) -> bytes:
        """Returns the data for a given CID. Raises an exception if the CID doesn't exist."""
        if cid not in self.datastore:
            raise ValueError(f"CID {cid} not found in fake IPFS.")
        return self.datastore[cid]


# Example usage:
ipfs = FakeIPFS()

# Add data to our fake IPFS.
data = b"This is some test data."
cid = ipfs.add(data)

# Retrieve the data using its CID.
retrieved_data = ipfs.cat(cid)
print(retrieved_data.decode('utf-8'))  # Outputs: This is some test data
