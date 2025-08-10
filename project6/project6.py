import hashlib
from typing import List, Optional, Tuple


class MerkleTree:
    """
    Merkle树（哈希树）实现，支持生成和验证存在性证明、不存在性证明。
    核心功能：通过逐层哈希聚合，实现高效的数据完整性验证，常用于区块链、分布式存储等场景。
    """

    def __init__(self, leaves: List[bytes]):
        """
        初始化Merkle树

        参数:
            leaves: 叶子节点列表（每个元素为bytes类型的哈希值）
        属性:
            tree: 完整的树结构，按层次存储（tree[0]为叶子层，tree[-1]为根节点层）
            root: 根哈希（树的顶层哈希，用于验证数据完整性）
            leaf_count: 原始叶子节点数量（未补全前的数量）
            leaves: 叶子节点哈希列表（可能包含补全的节点，确保层数为2的幂）
        """
        # 构建完整的树结构（每层节点列表）
        self.tree = self._build_tree(leaves)
        # 根哈希（若树为空则为None）
        self.root = self.tree[-1][0] if self.tree else None
        # 原始叶子节点数量（未补全时的数量）
        self.leaf_count = len(leaves)
        # 叶子层节点（可能包含补全节点，确保偶数个）
        self.leaves = self.tree[0] if self.tree else []

    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """
        迭代构建Merkle树，从叶子层向上生成各层节点，直到根节点

        参数:
            leaves: 原始叶子节点列表（哈希值）
        返回:
            树的层次结构（每层节点为哈希值列表，从叶子到根）
        逻辑:
            1. 从叶子层开始，逐层向上聚合
            2. 每层节点两两合并：父节点哈希 = SHA256(左子节点哈希 + 右子节点哈希)
            3. 若节点数为奇数，最后一个节点与自身合并（确保每层节点数为偶数）
            4. 重复直到生成根节点（单节点层）
        """
        if not leaves:
            return []

        # 初始化树结构，第一层为叶子层
        tree = [leaves.copy()]
        # 当前层节点（初始为叶子层）
        current_level = leaves.copy()

        # 循环向上构建，直到当前层只有1个节点（根节点）
        while len(current_level) > 1:
            next_level = []  # 下一层节点列表
            # 两两处理当前层节点
            for i in range(0, len(current_level), 2):
                left = current_level[i]  # 左子节点
                # 若i+1超出范围（奇数节点），右子节点取左子节点自身
                right = current_level[i + 1] if (i + 1) < len(current_level) else left
                # 计算父节点哈希（拼接左右子节点后哈希）
                parent = hashlib.sha256(left + right).digest()
                next_level.append(parent)
            # 将下一层加入树结构
            tree.append(next_level)
            # 进入下一层继续构建
            current_level = next_level

        return tree

    def get_inclusion_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """
        生成存在性证明：证明指定索引的叶子节点属于当前Merkle树

        参数:
            index: 叶子节点的索引（从0开始）
        返回:
            证明列表，每个元素为 tuple(兄弟节点哈希, 是否为左兄弟)
            - 兄弟节点哈希：用于向上聚合计算的相邻节点哈希
            - 是否为左兄弟：True表示该兄弟节点在左侧，False表示在右侧
        逻辑:
            1. 从目标叶子节点开始，逐层向上遍历
            2. 每层记录目标节点的兄弟节点哈希及位置（左/右）
            3. 最终证明长度等于树的高度（log2(叶子数)）
        """
        # 索引无效（超出原始叶子数量范围），返回空证明
        if index < 0 or index >= self.leaf_count:
            return []

        proof = []
        current_index = index  # 当前层目标节点的索引

        # 遍历除根节点外的所有层（从叶子层到根的下一层）
        for level in range(len(self.tree) - 1):
            current_level = self.tree[level]  # 当前层节点列表
            # 判断当前节点是否为左子节点（偶数索引为左，奇数为右）
            is_left = current_index % 2 == 0
            # 计算兄弟节点索引（左节点的兄弟为右邻，右节点的兄弟为左邻）
            sibling_index = current_index + 1 if is_left else current_index - 1

            # 若兄弟索引超出当前层范围（奇数节点补全场景），兄弟哈希取当前节点自身
            if sibling_index < len(current_level):
                sibling_hash = current_level[sibling_index]
            else:
                sibling_hash = current_level[current_index]

            # 记录证明：(兄弟哈希, 兄弟是否为左节点)
            # 注：若当前节点是左节点，兄弟是右节点，则"兄弟是否为左节点"为False
            proof.append((sibling_hash, not is_left))
            # 计算当前节点在上一层的索引（整除2）
            current_index = current_index // 2

        return proof

    @staticmethod
    def verify_inclusion(
            leaf_hash: bytes,
            index: int,
            proof: List[Tuple[bytes, bool]],
            root_hash: bytes
    ) -> bool:
        """
        验证存在性证明：检查指定叶子节点是否属于根哈希对应的Merkle树

        参数:
            leaf_hash: 待验证的叶子节点哈希
            index: 叶子节点的索引
            proof: 存在性证明列表（由get_inclusion_proof生成）
            root_hash: 基准根哈希
        返回:
            验证结果（True表示有效，False表示无效）
        逻辑:
            1. 从叶子哈希开始，结合证明中的兄弟节点逐层向上计算
            2. 每层根据兄弟节点的位置（左/右）拼接哈希
            3. 最终计算结果若与根哈希一致，则证明有效
        """
        # 特殊情况：树只有一个节点（无证明，直接比较叶子与根）
        if not proof:
            return leaf_hash == root_hash

        current_hash = leaf_hash  # 从叶子哈希开始计算
        current_index = index

        # 逐层应用证明，计算上层哈希
        for sibling_hash, is_sibling_left in proof:
            if is_sibling_left:
                # 兄弟节点在左侧：父哈希 = SHA256(兄弟哈希 + 当前哈希)
                current_hash = hashlib.sha256(sibling_hash + current_hash).digest()
            else:
                # 兄弟节点在右侧：父哈希 = SHA256(当前哈希 + 兄弟哈希)
                current_hash = hashlib.sha256(current_hash + sibling_hash).digest()
            # 更新当前索引（上一层的位置）
            current_index = current_index // 2

        # 最终计算结果与根哈希一致则有效
        return current_hash == root_hash

    def get_exclusion_proof(self, target_index: int) -> Tuple[
        Optional[Tuple[int, List[Tuple[bytes, bool]]]],
        Optional[Tuple[int, List[Tuple[bytes, bool]]]]
    ]:
        """
        生成不存在性证明：证明指定索引的叶子节点**不存在**于当前Merkle树

        参数:
            target_index: 待证明不存在的索引
        返回:
            左邻居证明和右邻居证明的元组：
            - 左邻居证明：(左邻居索引, 左邻居的存在性证明)，若不存在则为None
            - 右邻居证明：(右邻居索引, 右邻居的存在性证明)，若不存在则为None
        逻辑:
            1. 不存在性证明依赖"相邻存在节点"：若目标索引左右均有相邻节点，且两节点连续，
               则说明目标索引无节点
            2. 左邻居：目标索引左侧最大的有效索引（存在节点）
            3. 右邻居：目标索引右侧最小的有效索引（存在节点）
        """
        # 目标索引无效（小于0或已存在节点），返回空证明
        if target_index < 0 or target_index < self.leaf_count:
            return (None, None)

        # 寻找左侧最大的有效索引（存在节点的索引）
        left_index = target_index - 1
        # 若左索引超出原始叶子范围，继续左移
        while left_index >= 0 and left_index >= self.leaf_count:
            left_index -= 1

        # 寻找右侧最小的有效索引（存在节点的索引）
        right_index = target_index + 1
        # 叶子层最大可能索引（含补全节点）
        max_possible_index = len(self.leaves) - 1
        # 若右索引超出原始叶子范围，继续右移
        while right_index <= max_possible_index and right_index >= self.leaf_count:
            right_index += 1
        # 若右索引仍超出原始叶子范围，则无右邻居
        if right_index >= self.leaf_count:
            right_index = None

        # 生成左邻居的存在性证明
        left_proof = None
        if left_index >= 0:
            # 获取左邻居的存在性证明
            proof = self.get_inclusion_proof(left_index)
            left_proof = (left_index, proof)

        # 生成右邻居的存在性证明
        right_proof = None
        if right_index is not None and right_index < self.leaf_count:
            # 获取右邻居的存在性证明
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
        """
        验证不存在性证明：检查指定索引的叶子节点是否确实不存在

        参数:
            target_index: 待验证的不存在索引
            left_proof: 左邻居证明（由get_exclusion_proof生成）
            right_proof: 右邻居证明（由get_exclusion_proof生成）
            leaves: 原始叶子节点列表
            root_hash: 基准根哈希
        返回:
            验证结果（True表示不存在，False表示存在或证明无效）
        逻辑:
            1. 验证目标索引确实超出原始叶子范围
            2. 验证左/右邻居的存在性证明有效
            3. 验证左邻居在目标左侧、右邻居在目标右侧
            4. 验证左右邻居连续（中间无其他节点）
        """
        leaf_count = len(leaves)
        # 目标索引在有效范围内（存在节点），直接返回False
        if target_index < 0 or target_index < leaf_count:
            return False

        # 验证左邻居证明
        left_valid = False
        left_index = -1
        if left_proof:
            left_index, proof = left_proof
            # 左邻居索引必须有效（在叶子范围内）
            if left_index < 0 or left_index >= leaf_count:
                return False
            # 验证左邻居的存在性证明
            left_valid = MerkleTree.verify_inclusion(
                leaves[left_index], left_index, proof, root_hash
            )
            # 左邻居必须在目标索引左侧
            if left_index >= target_index:
                return False

        # 验证右邻居证明
        right_valid = False
        right_index = -1
        if right_proof:
            right_index, proof = right_proof
            # 右邻居索引必须有效（在叶子范围内）
            if right_index < 0 or right_index >= leaf_count:
                return False
            # 验证右邻居的存在性证明
            right_valid = MerkleTree.verify_inclusion(
                leaves[right_index], right_index, proof, root_hash
            )
            # 右邻居必须在目标索引右侧
            if right_index <= target_index:
                return False

        # 至少需要一个邻居的证明有效
        if not left_valid and not right_valid:
            return False

        # 若左右邻居均存在，需验证两者连续（中间无其他节点）
        if left_valid and right_valid and (left_index + 1 != right_index):
            return False

        return True


def generate_large_leaves(count: int) -> List[bytes]:
    """
    生成大量叶子节点哈希（用于测试）

    参数:
        count: 叶子节点数量
    返回:
        叶子节点哈希列表（每个元素为SHA256(原始值)的结果）
    说明:
        原始值格式为b"Leaf_1", b"Leaf_2", ..., 哈希后作为叶子节点
    """
    leaves = []
    for i in range(count):
        # 生成原始值（如b"Leaf_1"）
        leaf_value = f"Leaf_{i + 1}".encode()
        # 计算原始值的SHA256哈希作为叶子节点
        leaf_hash = hashlib.sha256(leaf_value).digest()
        leaves.append(leaf_hash)
    return leaves


if __name__ == "__main__":
    # 生成10万个叶子节点（模拟大规模数据）
    print("生成10万个叶子节点...")
    leaves = generate_large_leaves(100000)
    print(f"叶子节点数量: {len(leaves)}")

    # 构建Merkle树
    print("构建Merkle树...")
    merkle_tree = MerkleTree(leaves)
    print(f"Merkle树根哈希: {merkle_tree.root.hex()}\n")

    # 测试存在性证明（验证指定索引的叶子节点存在）
    test_indexes = [7, 761, 99999]  # 测试3个不同索引
    for idx in test_indexes:
        # 生成存在性证明
        proof = merkle_tree.get_inclusion_proof(idx)
        print(f"存在性证明 (索引 {idx}):")
        print(f"  证明长度: {len(proof)}（树高为log2(叶子数)，约{len(proof)}层）")
        # 验证证明有效性
        is_valid = MerkleTree.verify_inclusion(
            leaves[idx], idx, proof, merkle_tree.root
        )
        print(f"  验证结果: {'有效' if is_valid else '无效'}\n")

    # 测试不存在性证明（验证超出范围的索引不存在）
    ex_index = 100007  # 超出10万叶子的范围（原始叶子最大索引为99999）
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