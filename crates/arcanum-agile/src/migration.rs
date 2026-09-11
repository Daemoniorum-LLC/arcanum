//! Algorithm migration tools.
//!
//! Re-encrypt data with newer algorithms.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use crate::containers::AgileCiphertext;
use crate::errors::{AgileError, AgileResult};
use crate::registry::AlgorithmId;

/// Options for batch migration.
#[derive(Debug, Clone)]
pub struct MigrationOptions {
    /// Target algorithm
    pub target_algorithm: AlgorithmId,
    /// Enable checkpointing for resumable migrations
    pub checkpoint: bool,
    /// Number of parallel workers
    pub parallelism: usize,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            target_algorithm: AlgorithmId::Aes256Gcm,
            checkpoint: true,
            parallelism: 4,
        }
    }
}

/// Progress of a migration operation.
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    /// Total items to migrate
    pub total: usize,
    /// Items completed
    pub completed: usize,
    /// Items failed
    pub failed: usize,
    /// Current item being processed
    pub current: Option<String>,
}

impl MigrationProgress {
    /// Get completion percentage.
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.completed as f64 / self.total as f64) * 100.0
        }
    }
}

/// Migrate a single container to a new algorithm.
pub fn migrate_container(
    container: &AgileCiphertext,
    old_key: &[u8],
    new_key: &[u8],
    target_algorithm: AlgorithmId,
) -> AgileResult<AgileCiphertext> {
    // Decrypt with old key
    let plaintext = container.decrypt(old_key)?;

    // Re-encrypt with new algorithm and key
    AgileCiphertext::encrypt(target_algorithm, new_key, &plaintext)
}

/// Batch migration for multiple containers.
pub struct BatchMigration {
    options: MigrationOptions,
    progress: MigrationProgress,
}

impl BatchMigration {
    /// Create a new batch migration.
    pub fn new(options: MigrationOptions) -> Self {
        Self {
            options,
            progress: MigrationProgress {
                total: 0,
                completed: 0,
                failed: 0,
                current: None,
            },
        }
    }

    /// Get current progress.
    pub fn progress(&self) -> &MigrationProgress {
        &self.progress
    }

    /// Run the migration on a set of containers.
    pub fn run<F>(
        &mut self,
        containers: &[AgileCiphertext],
        old_key: &[u8],
        new_key: &[u8],
        mut on_complete: F,
    ) -> AgileResult<Vec<AgileCiphertext>>
    where
        F: FnMut(&MigrationProgress),
    {
        self.progress.total = containers.len();
        let mut results = Vec::with_capacity(containers.len());

        for (i, container) in containers.iter().enumerate() {
            self.progress.current = Some(format!("Container {}/{}", i + 1, containers.len()));

            match migrate_container(container, old_key, new_key, self.options.target_algorithm) {
                Ok(migrated) => {
                    results.push(migrated);
                    self.progress.completed += 1;
                }
                Err(_) => {
                    self.progress.failed += 1;
                    // Continue with other containers
                }
            }

            on_complete(&self.progress);
        }

        if self.progress.failed > 0 {
            return Err(AgileError::MigrationFailed {
                reason: format!("{} containers failed to migrate", self.progress.failed),
            });
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_progress() {
        let progress = MigrationProgress {
            total: 100,
            completed: 50,
            failed: 0,
            current: None,
        };

        assert_eq!(progress.percentage(), 50.0);
    }
}
