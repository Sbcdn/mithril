//! Bounded, keyed cache of block-range-roots Merkle maps used by the Cardano
//! transactions provers.
//!
//! A proof for a given `up_to` block number must be computed against the Merkle map
//! built from the block-range-roots at or below `up_to`, whose root is the one signed
//! by the certificate with that beacon. Keying the cache by `up_to` therefore lets a
//! single aggregator serve proofs for many certified tips at once, while the
//! least-recently-used bound keeps the memory footprint under operator control.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex, Weak},
};

use mithril_common::{
    StdResult,
    crypto_helper::{MKMap, MKMapNode, MKTreeStorer},
    entities::{BlockNumber, BlockRange},
};
use mithril_resource_pool::ResourcePool;
use rayon::prelude::*;

/// A cached block-range-roots Merkle map, parameterized by its tree storer.
pub type CachedMerkleMap<S> = MKMap<BlockRange, MKMapNode<BlockRange, S>, S>;

/// A pool of identical cached Merkle maps for one `up_to`, allowing concurrent proofs.
pub type CachedMerkleMapPool<S> = ResourcePool<CachedMerkleMap<S>>;

/// Bounded, keyed cache of Merkle map pools (one pool per `up_to` block number).
pub struct KeyedMerkleMapCache<S: MKTreeStorer> {
    max_entries: usize,
    pool_size: usize,
    entries: Mutex<CacheEntries<S>>,
    /// Per-key build gates: builds of the same `up_to` are serialized (built once),
    /// while builds of distinct tips proceed concurrently. Gates are dropped once no
    /// builder holds them.
    build_gates: Mutex<HashMap<BlockNumber, Weak<tokio::sync::Mutex<()>>>>,
}

struct CacheEntries<S: MKTreeStorer> {
    pools: HashMap<BlockNumber, Arc<CachedMerkleMapPool<S>>>,
    /// Access order, least-recently-used at the front.
    lru: VecDeque<BlockNumber>,
}

impl<S: MKTreeStorer> CacheEntries<S> {
    fn touch(&mut self, up_to: BlockNumber) {
        if let Some(index) = self.lru.iter().position(|key| *key == up_to) {
            self.lru.remove(index);
        }
        self.lru.push_back(up_to);
    }

    fn get(&mut self, up_to: BlockNumber) -> Option<Arc<CachedMerkleMapPool<S>>> {
        let pool = self.pools.get(&up_to).cloned()?;
        self.touch(up_to);
        Some(pool)
    }

    fn insert(
        &mut self,
        up_to: BlockNumber,
        pool: Arc<CachedMerkleMapPool<S>>,
        max_entries: usize,
    ) {
        self.pools.insert(up_to, pool);
        self.touch(up_to);
        while self.lru.len() > max_entries {
            if let Some(evicted) = self.lru.pop_front() {
                self.pools.remove(&evicted);
            }
        }
    }
}

impl<S: MKTreeStorer> KeyedMerkleMapCache<S> {
    /// Create a cache holding at most `max_entries` tips, each backed by a pool of
    /// `pool_size` identical maps. Both bounds are clamped to at least one.
    pub fn new(max_entries: usize, pool_size: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            pool_size: pool_size.max(1),
            entries: Mutex::new(CacheEntries {
                pools: HashMap::new(),
                lru: VecDeque::new(),
            }),
            build_gates: Mutex::new(HashMap::new()),
        }
    }

    /// Number of cached tips.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().pools.len()
    }

    /// Whether the cache holds no tips.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the pool for `up_to`, building it with `build` on a cache miss.
    ///
    /// On a miss, the build runs under a per-key gate so concurrent requests for the
    /// same tip build it only once, while requests for other tips are not blocked.
    pub async fn get_or_try_init<F, Fut>(
        &self,
        up_to: BlockNumber,
        build: F,
    ) -> StdResult<Arc<CachedMerkleMapPool<S>>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = StdResult<CachedMerkleMap<S>>>,
    {
        if let Some(pool) = self.entries.lock().unwrap().get(up_to) {
            return Ok(pool);
        }

        let gate = self.build_gate(up_to);
        let _building = gate.lock().await;
        // Another request may have built this tip while we waited for the gate.
        if let Some(pool) = self.entries.lock().unwrap().get(up_to) {
            return Ok(pool);
        }

        let pool = Arc::new(self.build_pool(build().await?));
        self.entries
            .lock()
            .unwrap()
            .insert(up_to, pool.clone(), self.max_entries);

        Ok(pool)
    }

    /// Get or create the build gate for `up_to`, dropping gates no builder holds anymore.
    fn build_gate(&self, up_to: BlockNumber) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.build_gates.lock().unwrap();
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(&up_to).and_then(Weak::upgrade) {
            return gate;
        }

        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(up_to, Arc::downgrade(&gate));
        gate
    }

    /// Fill a pool with `pool_size` clones of the freshly built map.
    fn build_pool(&self, mk_map: CachedMerkleMap<S>) -> CachedMerkleMapPool<S> {
        let resources = (0..self.pool_size).into_par_iter().map(|_| mk_map.clone()).collect();

        ResourcePool::new(self.pool_size, resources)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mithril_common::crypto_helper::MKTreeStoreInMemory;

    use super::*;

    type TestCache = KeyedMerkleMapCache<MKTreeStoreInMemory>;

    fn empty_map() -> CachedMerkleMap<MKTreeStoreInMemory> {
        MKMap::new(&[]).unwrap()
    }

    #[tokio::test]
    async fn builds_once_per_key_then_serves_from_cache() {
        let cache = TestCache::new(8, 1);
        let builds = AtomicUsize::new(0);

        for _ in 0..3 {
            cache
                .get_or_try_init(BlockNumber(10), || async {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Ok(empty_map())
                })
                .await
                .unwrap();
        }

        assert_eq!(1, builds.load(Ordering::SeqCst));
        assert_eq!(1, cache.len());
    }

    #[tokio::test]
    async fn evicts_least_recently_used_when_over_capacity() {
        let cache = TestCache::new(2, 1);
        let build = || async { Ok(empty_map()) };

        cache.get_or_try_init(BlockNumber(10), build).await.unwrap();
        cache.get_or_try_init(BlockNumber(20), build).await.unwrap();
        // Access 10 so 20 becomes the least-recently-used.
        cache.get_or_try_init(BlockNumber(10), build).await.unwrap();
        // Inserting 30 evicts 20, not 10.
        cache.get_or_try_init(BlockNumber(30), build).await.unwrap();

        assert_eq!(2, cache.len());
        assert!(cache.entries.lock().unwrap().get(BlockNumber(10)).is_some());
        assert!(cache.entries.lock().unwrap().get(BlockNumber(30)).is_some());
        assert!(cache.entries.lock().unwrap().get(BlockNumber(20)).is_none());
    }

    #[tokio::test]
    async fn rebuilds_a_key_after_it_was_evicted() {
        let cache = TestCache::new(1, 1);
        let builds = AtomicUsize::new(0);
        let counting_build = || async {
            builds.fetch_add(1, Ordering::SeqCst);
            Ok(empty_map())
        };

        cache.get_or_try_init(BlockNumber(10), counting_build).await.unwrap();
        cache.get_or_try_init(BlockNumber(20), counting_build).await.unwrap();
        // 10 was evicted by 20, so it must be rebuilt.
        cache.get_or_try_init(BlockNumber(10), counting_build).await.unwrap();

        assert_eq!(3, builds.load(Ordering::SeqCst));
        assert_eq!(1, cache.len());
    }

    #[tokio::test]
    async fn does_not_cache_a_failed_build() {
        let cache = TestCache::new(4, 1);

        let result = cache
            .get_or_try_init(BlockNumber(10), || async {
                Err(anyhow::anyhow!("build failed"))
            })
            .await;

        assert!(result.is_err());
        assert!(cache.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_for_the_same_key_build_it_once() {
        let cache = Arc::new(TestCache::new(8, 1));
        let builds = Arc::new(AtomicUsize::new(0));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let builds = builds.clone();
            tasks.spawn(async move {
                cache
                    .get_or_try_init(BlockNumber(42), || async move {
                        builds.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok(empty_map())
                    })
                    .await
                    .unwrap();
            });
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(1, builds.load(Ordering::SeqCst));
        assert_eq!(1, cache.len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_for_distinct_keys_each_build() {
        let cache = Arc::new(TestCache::new(8, 1));
        let builds = Arc::new(AtomicUsize::new(0));

        let mut tasks = tokio::task::JoinSet::new();
        for key in 0..8u64 {
            let cache = cache.clone();
            let builds = builds.clone();
            tasks.spawn(async move {
                cache
                    .get_or_try_init(BlockNumber(key), || async move {
                        builds.fetch_add(1, Ordering::SeqCst);
                        Ok(empty_map())
                    })
                    .await
                    .unwrap();
            });
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(8, builds.load(Ordering::SeqCst));
        assert_eq!(8, cache.len());
    }
}
