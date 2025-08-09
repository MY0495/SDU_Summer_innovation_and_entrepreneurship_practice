import hashlib
from typing import List, Optional, Tuple, Any


class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        # 存储完整的树结构（每一层的节点）
        self.tree = self._build_tree(leaves)
        # 根哈希
        self.root = self.tree[-1][0] if self.tree else None
        # 原始叶子节点数量
        self.leaf_count = len(leaves)
        # 叶子节点哈希列表（可能包含补全的节点）
        self.leaves = self.tree[0] if self.tree else []

    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """迭代构建Merkle树，返回每一层的节点列表"""
        if not leaves:
            return []

        tree = [leaves.copy()]
        current_level = leaves.copy()

        # 构建直到根节点
        while len(current_level) > 1:
            next_level = []
            # 处理当前层节点，两两合并
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # 若为奇数，最后一个节点与自身合并
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                # 父节点哈希：SHA256(左哈希 + 右哈希)
                parent = hashlib.sha256(left + right).digest()
                next_level.append(parent)
            tree.append(next_level)
            current_level = next_level

        return tree

    def get_inclusion_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """生成存在性证明：返回(兄弟节点哈希, 是否为左兄弟)的列表"""
        if index < 0 or index >= self.leaf_count:
            return []

        proof = []
        current_index = index
        # 从叶子层向上遍历每一层
        for level in range(len(self.tree) - 1):  # 不包含根节点层
            current_level = self.tree[level]
            # 计算兄弟节点索引
            is_left = current_index % 2 == 0
            sibling_index = current_index + 1 if is_left else current_index - 1

            # 处理边界：若兄弟索引超出当前层，则使用当前节点自身（奇数情况）
            if sibling_index < len(current_level):
                sibling_hash = current_level[sibling_index]
            else:
                sibling_hash = current_level[current_index]  # 自合并情况

            proof.append((sibling_hash, not is_left))  # 记录兄弟是否为左节点
            # 计算上一层的索引
            current_index = current_index // 2

        return proof

    @staticmethod
    def verify_inclusion(
            leaf_hash: bytes,
            index: int,
            proof: List[Tuple[bytes, bool]],
            root_hash: bytes
    ) -> bool:
        """验证存在性证明"""
        if not proof and root_hash == leaf_hash:
            return True  # 只有一个节点的情况

        current_hash = leaf_hash
        current_index = index

        for sibling_hash, is_sibling_left in proof:
            if is_sibling_left:
                # 兄弟在左，当前节点在右：parent = hash(sibling + current)
                current_hash = hashlib.sha256(sibling_hash + current_hash).digest()
            else:
                # 兄弟在右，当前节点在左：parent = hash(current + sibling)
                current_hash = hashlib.sha256(current_hash + sibling_hash).digest()
            current_index = current_index // 2

        return current_hash == root_hash

    def get_exclusion_proof(self, target_index: int) -> Tuple[
        Optional[Tuple[int, List[Tuple[bytes, bool]]]],  # 左邻居证明
        Optional[Tuple[int, List[Tuple[bytes, bool]]]]  # 右邻居证明
    ]:
        """生成不存在性证明：返回左右邻居的存在性证明"""
        if target_index < 0 or target_index < self.leaf_count:
            return (None, None)  # 目标索引存在或无效

        # 找到左侧最大的存在索引
        left_index = target_index - 1
        while left_index >= 0 and left_index >= self.leaf_count:
            left_index -= 1

        # 找到右侧最小的存在索引
        right_index = target_index + 1
        # 最大可能的叶子索引（考虑补全后的情况）
        max_possible_index = len(self.leaves) - 1
        while right_index <= max_possible_index and right_index >= self.leaf_count:
            right_index += 1
        # 右侧索引不能超过原始叶子数
        if right_index >= self.leaf_count:
            right_index = None

        # 生成左邻居证明
        left_proof = None
        if left_index >= 0:
            proof = self.get_inclusion_proof(left_index)
            left_proof = (left_index, proof)

        # 生成右邻居证明
        right_proof = None
        if right_index is not None and right_index < self.leaf_count:
            proof = self.get_inclusion_proof(right_index)
            right_proof = (right_index, proof)

        return (left_proof, right_proof)

    @staticmethod
    def verify_exclusion(
            target_index: int,
            left_proof: Optional[Tuple[int, List[Tuple[bytes, bool]]]],
            right_proof: Optional[Tuple[int, List[Tuple[bytes, bool]]]],
            leaves: List[bytes],
            root_hash: bytes
    ) -> bool:
        """验证不存在性证明"""
        # 目标索引必须超出范围
        leaf_count = len(leaves)
        if target_index < 0 or target_index < leaf_count:
            return False

        # 验证左邻居证明
        left_valid = False
        left_index = -1
        if left_proof:
            left_index, proof = left_proof
            if left_index < 0 or left_index >= leaf_count:
                return False
            # 验证左邻居的存在性证明
            left_valid = MerkleTree.verify_inclusion(
                leaves[left_index], left_index, proof, root_hash
            )
            # 左邻居必须在目标左侧
            if left_index >= target_index:
                return False

        # 验证右邻居证明
        right_valid = False
        right_index = -1
        if right_proof:
            right_index, proof = right_proof
            if right_index < 0 or right_index >= leaf_count:
                return False
            # 验证右邻居的存在性证明
            right_valid = MerkleTree.verify_inclusion(
                leaves[right_index], right_index, proof, root_hash
            )
            # 右邻居必须在目标右侧
            if right_index <= target_index:
                return False

        # 至少需要一个邻居有效
        if not left_valid and not right_valid:
            return False

        # 左右邻居必须相邻（中间无其他节点）
        if left_valid and right_valid and (left_index + 1 != right_index):
            return False

        return True


# 生成10万个叶子节点（每个叶子为哈希值）
def generate_large_leaves(count: int) -> List[bytes]:
    leaves = []
    for i in range(count):
        # 叶子原始值：b"Leaf_1", b"Leaf_2"...
        leaf_value = f"Leaf_{i + 1}".encode()
        # 叶子哈希：SHA256(原始值)
        leaf_hash = hashlib.sha256(leaf_value).digest()
        leaves.append(leaf_hash)
    return leaves


if __name__ == "__main__":
    # 生成10万个叶子节点
    print("生成10万个叶子节点...")
    leaves = generate_large_leaves(100000)
    print(f"叶子节点数量: {len(leaves)}")

    # 构建Merkle树
    print("构建Merkle树...")
    merkle_tree = MerkleTree(leaves)
    print(f"Merkle树根哈希: {merkle_tree.root.hex()}\n")

    # 测试存在性证明（正常索引）
    test_indexes = [7, 761, 99999]
    for idx in test_indexes:
        proof = merkle_tree.get_inclusion_proof(idx)
        print(f"存在性证明 (索引 {idx}):")
        print(f"  证明长度: {len(proof)}")
        # 验证证明
        is_valid = MerkleTree.verify_inclusion(
            leaves[idx], idx, proof, merkle_tree.root
        )
        print(f"  验证结果: {'有效' if is_valid else '无效'}\n")

    # 测试不存在性证明（超出范围的索引）
    ex_index = 100007  # 超出10万叶子的范围
    left_proof, right_proof = merkle_tree.get_exclusion_proof(ex_index)
    print(f"不存在性证明 (索引 {ex_index}):")
    if left_proof:
        print(f"  左邻居索引: {left_proof[0]}, 证明长度: {len(left_proof[1])}")
    if right_proof:
        print(f"  右邻居索引: {right_proof[0]}, 证明长度: {len(right_proof[1])}")
    # 验证不存在性证明
    ex_valid = MerkleTree.verify_exclusion(
        ex_index, left_proof, right_proof, leaves, merkle_tree.root
    )
    print(f"  验证结果: {'有效' if ex_valid else '无效'}")
