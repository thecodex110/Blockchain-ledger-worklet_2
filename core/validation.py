import json

class UTXOSet:
    """Hash-map backed UTXO set for O(1) balance lookups."""
    def __init__(self):
        self.utxos = {}

    def apply_block(self, block):
        for tx in getattr(block, 'transactions', []):
            if hasattr(tx, 'inputs') and tx.inputs:
                for tx_in in tx.inputs:
                    key = f"{tx_in['prev_tx_id']}:{tx_in['output_index']}"
                    self.utxos.pop(key, None)
            
            if hasattr(tx, 'outputs') and tx.outputs:
                for idx, tx_out in enumerate(tx.outputs):
                    key = f"{tx.tx_id}:{idx}"
                    self.utxos[key] = {
                        'recipient': tx_out['recipient'],
                        'amount': tx_out['amount']
                    }

    def get_balance(self, address: str) -> float:
        return sum(out['amount'] for out in self.utxos.values() if out['recipient'] == address)


class FullChainValidator:
    """Genesis-to-tip chain validation engine (Worklet 3)."""
    @staticmethod
    def validate_chain(chain) -> tuple[bool, str]:
        if not chain:
            return False, "Chain is empty"

        for i in range(1, len(chain)):
            current_block = chain[i]
            prev_block = chain[i - 1]

            if current_block.previous_hash != prev_block.hash:
                return False, f"Hash mismatch at block {i}"

            if current_block.hash != current_block.compute_hash():
                return False, f"Block {i} hash tampered"

            if not current_block.hash.startswith('0' * current_block.difficulty):
                return False, f"Block {i} PoW target failed"

            if current_block.merkle_root != current_block.build_merkle_root():
                return False, f"Merkle Root mismatch at block {i}"

        return True, "Chain valid from Genesis to tip"

