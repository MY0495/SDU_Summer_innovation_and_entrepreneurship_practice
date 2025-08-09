# 根据RFC6962构建Merkle树（10w叶子节点），并构建叶子的存在性证明和不存在性证明
## 简介
Merkle Tree（梅克尔树）是一种加密哈希树，广泛应用于区块链、分布式系统及数据完整性验证。它可以有效地验证数据的存在性和完整性，且具备较强的抗篡改性。通过对叶子节点进行哈希，再逐层合并生成父节点，最终形成一个根哈希，可以在不传输整个数据集的情况下，验证任意节点的存在性。

## 原理
Merkle Tree 的主要结构如下：
每个叶子节点表示具体数据的哈希值。
每对叶子节点的哈希值合并成一个父节点，继续向上重复，直至形成根节点。
通过存在性证明，可以使用叶子节点及其兄弟节点的哈希来验证该节点是否存在于树中。
不存在性证明则显示相邻叶子节点的存在性，来确保目标节点在树中不存在。

## 核心代码解释
### MerkleTree 类

class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.tree = self._build_tree(leaves)
        self.root = self.tree[-1][0] if self.tree else None
        self.leaf_count = len(leaves)
        self.leaves = self.tree[0] if self.tree else []
__init__ 方法初始化Merkle树，接受叶子节点（哈希值）并构建树结构。
_build_tree 是内部辅助方法，负责构建完整的树结构并返回每一层的节点。

### 构建树

def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
    if not leaves:
        return []
    tree = [leaves.copy()]
    current_level = leaves.copy()
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            parent = hashlib.sha256(left + right).digest()
            next_level.append(parent)
        tree.append(next_level)
        current_level = next_level
        
    return tree
该方法通过不断合并当前层节点的哈希，生成上一层的父节点，直至只剩下一个根哈希。
### 存在性证明

def get_inclusion_proof(self, index: int) -> List[Tuple[bytes, bool]]:
    # 生成存在性证明：返回(兄弟节点哈希, 是否为左兄弟)的列表
该方法生成给定索引的叶子节点的存在性证明，返回兄弟节点的哈希列表及其相对位置。
验证存在性
python
运行
@staticmethod
def verify_inclusion(
    leaf_hash: bytes,
    index: int,
    proof: List[Tuple[bytes, bool]],
    root_hash: bytes
) -> bool:
    # 验证存在性证明
    ...
该静态方法用来验证生成的存在性证明是否有效。

### 不存在性证明

def get_exclusion_proof(self, target_index: int) -> Tuple[
    Optional[Tuple[int, List[Tuple[bytes, bool]]]],
    Optional[Tuple[int, List[Tuple[bytes, bool]]]]
]:
    # 生成不存在性证明：返回左右邻居的存在性证明
该方法为超出范围的目标索引生成左右邻居的存在性证明。

### 验证不存在性

@staticmethod
def verify_exclusion(
    target_index: int,
    left_proof: Optional[Tuple[int, List[Tuple[bytes, bool]]]],
    right_proof: Optional[Tuple[int, List[Tuple[bytes, bool]]]],
    leaves: List[bytes],
    root_hash: bytes
) -> bool:
    # 验证不存在性证明
验证给定索引的不存在性证明，以确定其确实不在Merkle树中。
使用示例
生成并验证Merkle树
在 __main__ 中，示例代码如下：


if __name__ == "__main__":
    leaves = generate_large_leaves(100000)
    merkle_tree = MerkleTree(leaves)
    
    test_indexes = [7, 761, 99999]
    for idx in test_indexes:
        proof = merkle_tree.get_inclusion_proof(idx)
        is_valid = MerkleTree.verify_inclusion(leaves[idx], idx, proof, merkle_tree.root)
    
    ex_index = 100007  # 超出10万叶子的范围
    left_proof, right_proof = merkle_tree.get_exclusion_proof(ex_index)
    ex_valid = MerkleTree.verify_exclusion(ex_index, left_proof, right_proof, leaves, merkle_tree.root)
此示例生成10万个叶子节点，构建Merkle树，并测试存在性与不存在性证明的验证。

## 结论
该Merkle树实现提供了在大规模数据集上进行存在性和不存在性证明的高效方法。使用SHA256加密哈希确保了内容的完整性与安全性。对于分布式系统和区块链领域，该实现可以增强数据验证和防篡改能力。

## 说明
详细的实现代码见 源代码文件project4-c。
