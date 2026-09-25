import json
import os
import threading
from core.validation import FullChainValidator, UTXOSet

class BlockchainLedger:
    """Thread-safe ledger with cumulative-work fork resolution."""
    def __init__(self, storage_path="chain_state.json"):
        self.chain = []
        self.utxo_set = UTXOSet()
        self.lock = threading.Lock()
        self.storage_path = storage_path

    def resolve_fork(self, competing_chain) -> bool:
        with self.lock:
            valid, _ = FullChainValidator.validate_chain(competing_chain)
            if not valid:
                return False

            local_work = sum(2 ** b.difficulty for b in self.chain)
            competing_work = sum(2 ** b.difficulty for b in competing_chain)

            if competing_work > local_work:
                self.chain = competing_chain
                self.utxo_set = UTXOSet()
                for block in self.chain:
                    self.utxo_set.apply_block(block)
                return True
            return False

    def persist_to_disk(self):
        with self.lock:
            serialized = [b.to_dict() for b in self.chain]
            with open(self.storage_path, "w") as f:
                json.dump(serialized, f, indent=4)

    def reload_and_validate(self, block_class_factory) -> bool:
        if not os.path.exists(self.storage_path):
            return False

        with open(self.storage_path, "r") as f:
            data = json.load(f)

        reconstructed_chain = [block_class_factory.from_dict(b) for b in data]
        valid, msg = FullChainValidator.validate_chain(reconstructed_chain)
        if not valid:
            raise ValueError(f"Corrupted state: {msg}")

        self.chain = reconstructed_chain
        self.utxo_set = UTXOSet()
        for block in self.chain:
            self.utxo_set.apply_block(block)
        return True

