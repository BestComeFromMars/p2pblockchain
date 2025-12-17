# blockchain.py
from block import Block, DIFFICULTY

class Blockchain:
    def __init__(self, difficulty: int = DIFFICULTY):
        self.chain = []
        self.difficulty = difficulty

    def last_block(self):
        return self.chain[-1] if self.chain else None

    def is_valid_pow(self, block: Block) -> bool:
        prefix = '0' * self.difficulty
        return isinstance(block.hash, str) and block.hash.startswith(prefix) and block.hash == block.calculate_hash()

    def is_valid_new_block(self, block: Block, prev_block: Block) -> bool:
        if prev_block is None:
            return block.index == 0
        if prev_block.index + 1 != block.index:
            return False
        if prev_block.hash != block.previous_hash:
            return False
        if not self.is_valid_pow(block):
            return False
        return True

    def append_block(self, block: Block) -> bool:
        prev = self.last_block()
        if self.is_valid_new_block(block, prev):
            self.chain.append(block)
            return True
        return False

    def height(self):
        return len(self.chain)
