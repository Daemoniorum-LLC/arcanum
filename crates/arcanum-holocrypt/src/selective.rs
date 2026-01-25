//! Selective disclosure for HoloCrypt containers.
//!
//! Reveal specific chunks without exposing the entire container.
//! Uses BLAKE3 Merkle proofs for verification.

use crate::errors::{HoloCryptError, HoloCryptResult};
use serde::{Deserialize, Serialize};

#[cfg(feature = "merkle")]
use arcanum_hash::{Blake3, Hasher};

/// A Merkle proof for a specific chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkProof {
    /// Index of the chunk in the container
    chunk_index: usize,
    /// Total number of chunks (needed for verification)
    total_chunks: usize,
    /// Sibling hashes in the Merkle path (from leaf to root)
    siblings: Vec<[u8; 32]>,
    /// Direction flags: false = sibling is on right, true = sibling is on left
    directions: Vec<bool>,
}

impl ChunkProof {
    /// Create a new chunk proof.
    pub fn new(
        chunk_index: usize,
        total_chunks: usize,
        siblings: Vec<[u8; 32]>,
        directions: Vec<bool>,
    ) -> Self {
        Self {
            chunk_index,
            total_chunks,
            siblings,
            directions,
        }
    }

    /// Get the chunk index.
    pub fn chunk_index(&self) -> usize {
        self.chunk_index
    }

    /// Get the total number of chunks.
    pub fn total_chunks(&self) -> usize {
        self.total_chunks
    }

    /// Get the sibling hashes.
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    /// Get the path length.
    pub fn path_length(&self) -> usize {
        self.siblings.len()
    }

    /// Verify this proof against a Merkle root.
    #[cfg(feature = "merkle")]
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, chunk: &[u8], merkle_root: &[u8; 32]) -> bool {
        // Hash the chunk to get the leaf hash
        let mut current = Self::hash_leaf(chunk);

        // Walk up the tree
        for (sibling, &is_left) in self.siblings.iter().zip(&self.directions) {
            if is_left {
                // Sibling is on the left
                current = Self::hash_node(sibling, &current);
            } else {
                // Sibling is on the right
                current = Self::hash_node(&current, sibling);
            }
        }

        current == *merkle_root
    }

    /// Hash a leaf node.
    #[cfg(feature = "merkle")]
    fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"holocrypt-leaf");
        hasher.update(data);
        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Hash an internal node.
    #[cfg(feature = "merkle")]
    fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"holocrypt-node");
        hasher.update(left);
        hasher.update(right);
        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple format: chunk_index (8) + total_chunks (8) + path_len (8) + siblings + directions
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.chunk_index as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.total_chunks as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.siblings.len() as u64).to_le_bytes());
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling);
        }
        // Pack directions as bits
        let mut direction_bytes = vec![0u8; (self.directions.len() + 7) / 8];
        for (i, &dir) in self.directions.iter().enumerate() {
            if dir {
                direction_bytes[i / 8] |= 1 << (i % 8);
            }
        }
        bytes.extend_from_slice(&direction_bytes);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> HoloCryptResult<Self> {
        if bytes.len() < 24 {
            return Err(HoloCryptError::VerificationFailed {
                reason: "proof bytes too short".into(),
            });
        }

        let chunk_index = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let total_chunks = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let path_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;

        let siblings_start = 24;
        let siblings_end = siblings_start + path_len * 32;

        if bytes.len() < siblings_end {
            return Err(HoloCryptError::VerificationFailed {
                reason: "proof bytes incomplete".into(),
            });
        }

        let mut siblings = Vec::with_capacity(path_len);
        for i in 0..path_len {
            let start = siblings_start + i * 32;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[start..start + 32]);
            siblings.push(hash);
        }

        // Read direction bits
        let direction_bytes = &bytes[siblings_end..];
        let mut directions = Vec::with_capacity(path_len);
        for i in 0..path_len {
            if i / 8 < direction_bytes.len() {
                directions.push((direction_bytes[i / 8] >> (i % 8)) & 1 == 1);
            } else {
                directions.push(false);
            }
        }

        Ok(Self {
            chunk_index,
            total_chunks,
            siblings,
            directions,
        })
    }
}

/// Selective disclosure operations on HoloCrypt containers.
pub trait SelectiveDisclosure<T> {
    /// Reveal a specific chunk with its Merkle proof.
    fn reveal_chunk(&self, index: usize) -> HoloCryptResult<(Vec<u8>, ChunkProof)>;

    /// Verify a revealed chunk against the container's Merkle root.
    fn verify_revealed_chunk(&self, chunk: &[u8], proof: &ChunkProof) -> bool;
}

/// Configuration for chunking data.
#[derive(Debug, Clone, Copy)]
pub struct ChunkConfig {
    /// Size of each chunk in bytes
    pub chunk_size: usize,
    /// Minimum number of chunks
    pub min_chunks: usize,
    /// Maximum number of chunks
    pub max_chunks: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_size: 4096, // 4KB chunks
            min_chunks: 1,
            max_chunks: 1_000_000, // ~4GB max
        }
    }
}

/// Merkle tree builder for selective disclosure.
#[cfg(feature = "merkle")]
pub struct MerkleTreeBuilder {
    /// Leaf hashes
    leaves: Vec<[u8; 32]>,
    /// Tree levels (bottom to top)
    levels: Vec<Vec<[u8; 32]>>,
}

#[cfg(feature = "merkle")]
impl MerkleTreeBuilder {
    /// Create a new Merkle tree from chunks.
    pub fn from_chunks(chunks: &[&[u8]]) -> Self {
        if chunks.is_empty() {
            return Self {
                leaves: vec![],
                levels: vec![],
            };
        }

        // Hash all leaves
        let leaves: Vec<[u8; 32]> = chunks.iter().map(|c| ChunkProof::hash_leaf(c)).collect();

        // Build tree levels
        let mut levels = vec![leaves.clone()];
        let mut current = leaves.clone();

        while current.len() > 1 {
            let mut next_level = Vec::new();
            for pair in current.chunks(2) {
                let left = &pair[0];
                let right = if pair.len() > 1 { &pair[1] } else { &pair[0] };
                next_level.push(ChunkProof::hash_node(left, right));
            }
            levels.push(next_level.clone());
            current = next_level;
        }

        Self { leaves, levels }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        if let Some(top) = self.levels.last()
            && let Some(root) = top.first()
        {
            return *root;
        }
        // Empty tree - return special hash
        let mut hasher = Blake3::new();
        hasher.update(b"holocrypt-empty-merkle");
        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Generate a proof for a specific chunk index.
    pub fn generate_proof(&self, index: usize) -> Option<ChunkProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut current_index = index;

        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            // Get sibling hash (duplicate if at end of odd-length level)
            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                level[current_index]
            };

            siblings.push(sibling);
            // Direction: true if sibling is on the left (we are on the right)
            directions.push(current_index % 2 == 1);

            current_index /= 2;
        }

        Some(ChunkProof::new(
            index,
            self.leaves.len(),
            siblings,
            directions,
        ))
    }

    /// Get number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

/// Verify a chunk against a Merkle root.
#[cfg(feature = "merkle")]
#[must_use = "verification result must be checked"]
pub fn verify_chunk(chunk: &[u8], proof: &ChunkProof, merkle_root: &[u8; 32]) -> bool {
    proof.verify(chunk, merkle_root)
}

#[cfg(test)]
#[cfg(feature = "merkle")]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_single_chunk() {
        let data = b"single chunk data";
        let tree = MerkleTreeBuilder::from_chunks(&[data.as_slice()]);

        assert_eq!(tree.len(), 1);

        let proof = tree.generate_proof(0).unwrap();
        assert_eq!(proof.chunk_index(), 0);
        assert!(proof.verify(data, &tree.root()));
    }

    #[test]
    fn merkle_tree_multiple_chunks() {
        let chunks: Vec<&[u8]> = vec![b"chunk 0", b"chunk 1", b"chunk 2", b"chunk 3"];
        let tree = MerkleTreeBuilder::from_chunks(&chunks);

        assert_eq!(tree.len(), 4);

        // Verify each chunk
        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert_eq!(proof.chunk_index(), i);
            assert!(proof.verify(chunk, &tree.root()), "Failed for chunk {}", i);
        }
    }

    #[test]
    fn merkle_tree_odd_chunks() {
        let chunks: Vec<&[u8]> = vec![b"chunk 0", b"chunk 1", b"chunk 2"];
        let tree = MerkleTreeBuilder::from_chunks(&chunks);

        assert_eq!(tree.len(), 3);

        // Verify each chunk
        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(chunk, &tree.root()), "Failed for chunk {}", i);
        }
    }

    #[test]
    fn merkle_proof_fails_with_wrong_chunk() {
        let chunks: Vec<&[u8]> = vec![b"chunk 0", b"chunk 1"];
        let tree = MerkleTreeBuilder::from_chunks(&chunks);

        let proof = tree.generate_proof(0).unwrap();

        // Verify with wrong chunk data
        assert!(!proof.verify(b"wrong data", &tree.root()));
    }

    #[test]
    fn merkle_proof_fails_with_wrong_root() {
        let chunks: Vec<&[u8]> = vec![b"chunk 0", b"chunk 1"];
        let tree = MerkleTreeBuilder::from_chunks(&chunks);

        let proof = tree.generate_proof(0).unwrap();
        let wrong_root = [0u8; 32];

        assert!(!proof.verify(b"chunk 0", &wrong_root));
    }

    #[test]
    fn chunk_proof_serialization() {
        let chunks: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTreeBuilder::from_chunks(&chunks);

        let proof = tree.generate_proof(2).unwrap();
        let bytes = proof.to_bytes();
        let restored = ChunkProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.chunk_index(), restored.chunk_index());
        assert_eq!(proof.total_chunks(), restored.total_chunks());
        assert_eq!(proof.siblings(), restored.siblings());

        // Verify restored proof works
        assert!(restored.verify(b"c", &tree.root()));
    }

    #[test]
    fn merkle_tree_large() {
        // Test with 16 chunks
        let chunks: Vec<Vec<u8>> = (0..16)
            .map(|i| format!("chunk {}", i).into_bytes())
            .collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let tree = MerkleTreeBuilder::from_chunks(&chunk_refs);

        assert_eq!(tree.len(), 16);

        // Verify some chunks
        for i in [0, 5, 10, 15] {
            let proof = tree.generate_proof(i).unwrap();
            assert!(
                proof.verify(&chunks[i], &tree.root()),
                "Failed for chunk {}",
                i
            );
        }
    }

    #[test]
    fn merkle_tree_deterministic() {
        let chunks: Vec<&[u8]> = vec![b"a", b"b", b"c"];

        let tree1 = MerkleTreeBuilder::from_chunks(&chunks);
        let tree2 = MerkleTreeBuilder::from_chunks(&chunks);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn verify_chunk_standalone() {
        let chunks: Vec<&[u8]> = vec![b"data0", b"data1"];
        let tree = MerkleTreeBuilder::from_chunks(&chunks);
        let root = tree.root();

        let proof = tree.generate_proof(1).unwrap();

        // Use standalone function
        assert!(verify_chunk(b"data1", &proof, &root));
        assert!(!verify_chunk(b"wrong", &proof, &root));
    }
}
