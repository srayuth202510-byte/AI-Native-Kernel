#[cfg(feature = "rocksdb-warm")]
use parking_lot::Mutex;
#[cfg(not(feature = "rocksdb-warm"))]
use std::collections::HashMap;
use std::collections::VecDeque;
#[cfg(feature = "rocksdb-warm")]
use std::sync::Arc;
#[cfg(feature = "rocksdb-warm")]
use std::time::Duration;

#[cfg(feature = "rocksdb-warm")]
const ROCKSDB_TIMEOUT: Duration = Duration::from_secs(5);

/// โครงสร้างข้อมูลสำหรับเก็บหน้าบริบทแบบชั่วคราว (Warm Store)
///
/// **โหมดปกติ (default)**: จำลองด้วยหน่วยความจำ (HashMap) เหมาะสำหรับ CI และการทดสอบ
///
/// **โหมด RocksDB (`rocksdb-warm` feature)**: ใช้ RocksDB จริงบน NVMe
/// เปิดใช้งานด้วย `cargo build --features context-memory/rocksdb-warm`
/// เป้าหมาย: Cold→Warm load < 50ms P99 (ANK-012)
#[cfg(not(feature = "rocksdb-warm"))]
#[derive(Debug, Default)]
pub struct WarmStore {
    /// ตาราง HashMap สำหรับเก็บคีย์และข้อมูลบริบท (โหมดจำลอง)
    entries: HashMap<String, Vec<u8>>,
    /// คิวสองด้านสำหรับติดตามและจัดการคิวลำดับข้อมูลแบบ FIFO
    order: VecDeque<String>,
}

#[cfg(not(feature = "rocksdb-warm"))]
impl WarmStore {
    /// สร้างอินสแตนซ์ของ WarmStore ใหม่ที่มีค่าเริ่มต้นเป็นค่าว่าง
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ใส่ข้อมูลบริบทลงใน Warm Store
    pub fn insert(&mut self, key: String, value: Vec<u8>) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, value);
    }

    /// ดึงสำเนาข้อมูลบริบทตามคีย์ที่กำหนด (ถ้ามี)
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }

    /// ส่งคืนจำนวนข้อมูลบริบททั้งหมดที่จัดเก็บอยู่ในปัจจุบัน
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ตรวจสอบว่า Warm Store ว่างเปล่าหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// ลบและส่งคืนข้อมูลเก่าที่สุดตามลำดับ FIFO เพื่อย้ายไปยัง Cold Store
    pub fn evict_oldest(&mut self) -> Option<(String, Vec<u8>)> {
        let key = self.order.pop_front()?;
        self.entries.remove(&key).map(|value| (key, value))
    }

    /// ลบข้อมูลบริบทตาม key ออกจาก Warm Store และคืนค่า (ถ้ามี)
    /// ใช้สำหรับ tier migration (promote/demote) โดยตรง
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        if let Some(value) = self.entries.remove(key) {
            self.order.retain(|k| k != key);
            Some(value)
        } else {
            None
        }
    }
}

// ---- โหมด RocksDB จริง (feature = "rocksdb-warm") ----
// ANK-012: Warm tier (NVMe): RocksDB store สำหรับ Phase 1 production
#[cfg(feature = "rocksdb-warm")]
pub struct WarmStore {
    /// การเชื่อมต่อกับฐานข้อมูล RocksDB บน NVMe สำหรับ Warm tier จริง
    db: Option<Arc<rocksdb::DB>>,
    /// พาธสำหรับจัดเก็บ RocksDB เพื่อใช้ในการลบไฟล์เมื่อ drop
    path: std::path::PathBuf,
    /// คิวติดตามลำดับข้อมูล FIFO สำหรับการ evict ข้อมูลเก่า
    order: Mutex<VecDeque<String>>,
    /// นับจำนวนรายการเพื่อประเมิน len() โดยไม่ต้อง scan ทั้ง DB
    count: std::sync::atomic::AtomicUsize,
    /// บ่งชี้ว่าเป็น path ชั่วคราว (สำหรับ testing) หรือไม่ เพื่อลบเมื่อ drop
    is_temp: bool,
}

#[cfg(feature = "rocksdb-warm")]
impl Default for WarmStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "rocksdb-warm")]
fn rocksdb_timeout<T: Send + 'static>(
    db: &Arc<rocksdb::DB>,
    op: impl FnOnce(&rocksdb::DB) -> T + Send + 'static,
) -> Option<T> {
    let db = Arc::clone(db);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(op(&db));
    });
    rx.recv_timeout(ROCKSDB_TIMEOUT).ok()
}

#[cfg(feature = "rocksdb-warm")]
impl WarmStore {
    /// สร้าง WarmStore ที่ใช้ RocksDB ในพาธชั่วคราว (สำหรับ testing)
    /// ใน production ควรระบุพาธ NVMe จริงผ่าน config
    #[must_use]
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ank-warm-store-{}", uuid::Uuid::new_v4()));
        Self::new_with_path_internal(path, true)
    }

    /// สร้าง WarmStore ที่ใช้ RocksDB ในพาธที่กำหนด
    #[must_use]
    pub fn new_with_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        Self::new_with_path_internal(path.as_ref().to_path_buf(), false)
    }

    fn new_with_path_internal(path: std::path::PathBuf, is_temp: bool) -> Self {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Snappy);

        opts.increase_parallelism(4);
        opts.set_max_write_buffer_number(4);
        opts.set_min_write_buffer_number_to_merge(2);

        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_block_cache(&rocksdb::Cache::new_lru_cache(64 * 1024 * 1024));
        opts.set_block_based_table_factory(&block_opts);

        let db = open_rocksdb_with_timeout(opts, &path);

        let mut order_list = VecDeque::new();
        let mut count_val = 0;
        if let Some(ref db) = db {
            let iter = db.iterator(rocksdb::IteratorMode::Start);
            for (key_bytes, _) in iter.flatten() {
                if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                    order_list.push_back(key_str.to_string());
                    count_val += 1;
                }
            }
        }

        Self {
            db,
            path,
            order: Mutex::new(order_list),
            count: std::sync::atomic::AtomicUsize::new(count_val),
            is_temp,
        }
    }

    /// ใส่ข้อมูลบริบทลงใน RocksDB Warm Store
    pub fn insert(&mut self, key: String, value: Vec<u8>) {
        let db = match self.db.as_ref() {
            Some(db) => Arc::clone(db),
            None => return,
        };
        let key_for_op = key.clone();
        let value_for_op = value.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let is_new = db
                .get(key_for_op.as_bytes())
                .map(|v| v.is_none())
                .unwrap_or(true);
            let _ = db.put(key_for_op.as_bytes(), &value_for_op);
            let _ = tx.send(is_new);
        });
        let Ok(is_new) = rx.recv_timeout(ROCKSDB_TIMEOUT) else {
            tracing::warn!("RocksDB insert timed out for key: {}", key);
            return;
        };
        if is_new {
            let mut order = self.order.lock();
            order.push_back(key);
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// ดึงข้อมูลบริบทจาก RocksDB ตามคีย์ที่กำหนด
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let db = self.db.as_ref()?;
        let key_owned = key.to_owned();
        rocksdb_timeout(db, move |d| d.get(key_owned.as_bytes()).ok().flatten())?
    }

    /// ส่งคืนจำนวนรายการโดยประมาณ (ใช้ atomic counter)
    #[must_use]
    pub fn len(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// ตรวจสอบว่า Warm Store ว่างเปล่าหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// ลบและส่งคืนข้อมูลเก่าที่สุดตามลำดับ FIFO เพื่อย้ายไปยัง Cold Store
    pub fn evict_oldest(&mut self) -> Option<(String, Vec<u8>)> {
        let key = {
            let mut order = self.order.lock();
            order.pop_front()?
        };
        let db = self.db.as_ref()?;
        let key_owned = key.clone();
        let value = rocksdb_timeout(db, move |d| d.get(key_owned.as_bytes()).ok().flatten())??;
        let key_for_del = key.clone();
        rocksdb_timeout(db, move |d| d.delete(key_for_del.as_bytes()).ok());
        self.count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        Some((key, value))
    }

    /// ลบข้อมูลบริบทตาม key ออกจาก RocksDB Warm Store และคืนค่า (ถ้ามี)
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        let db = self.db.as_ref()?;
        let key_owned = key.to_owned();
        let value = rocksdb_timeout(db, move |d| d.get(key_owned.as_bytes()).ok().flatten())??;
        let key_for_del = key.to_owned();
        rocksdb_timeout(db, move |d| d.delete(key_for_del.as_bytes()).ok());
        let mut order = self.order.lock();
        order.retain(|k| k != key);
        self.count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        Some(value)
    }
}

#[cfg(feature = "rocksdb-warm")]
fn open_rocksdb_with_timeout(
    opts: rocksdb::Options,
    path: &std::path::Path,
) -> Option<Arc<rocksdb::DB>> {
    let path_display = path.display().to_string();
    let path_owned = path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let db = rocksdb::DB::open(&opts, &path_owned);
        let _ = tx.send(db);
    });
    match rx.recv_timeout(ROCKSDB_TIMEOUT) {
        Ok(Ok(db)) => Some(Arc::new(db)),
        _ => {
            tracing::warn!("RocksDB open timed out at path: {}", path_display);
            None
        }
    }
}

#[cfg(feature = "rocksdb-warm")]
impl Drop for WarmStore {
    fn drop(&mut self) {
        self.db.take();
        if self.is_temp {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(all(test, feature = "rocksdb-warm"))]
mod tests {
    use super::*;

    #[test]
    fn rocksdb_warm_store_true_persistence() {
        let path =
            std::env::temp_dir().join(format!("ank-test-persistent-{}", uuid::Uuid::new_v4()));

        // 1. Create a store, write data, and verify
        {
            let mut store = WarmStore::new_with_path(&path);
            store.insert("key1".to_string(), b"value1".to_vec());
            store.insert("key2".to_string(), b"value2".to_vec());
            assert_eq!(store.len(), 2);
            assert_eq!(store.get("key1"), Some(b"value1".to_vec()));
            assert_eq!(store.get("key2"), Some(b"value2".to_vec()));
            // Dropped here, closes DB, should NOT delete the directory because is_temp is false
        }

        // 2. Open it again with the same path, and verify that the data, count, and FIFO order are restored!
        {
            let mut store = WarmStore::new_with_path(&path);
            assert_eq!(store.len(), 2);
            assert_eq!(store.get("key1"), Some(b"value1".to_vec()));
            assert_eq!(store.get("key2"), Some(b"value2".to_vec()));

            // Verify order queue by evicting oldest (FIFO)
            let evicted1 = store.evict_oldest();
            assert!(evicted1.is_some());
            let (k1, v1) = evicted1.unwrap();
            assert_eq!(k1, "key1");
            assert_eq!(v1, b"value1".to_vec());

            let evicted2 = store.evict_oldest();
            assert!(evicted2.is_some());
            let (k2, v2) = evicted2.unwrap();
            assert_eq!(k2, "key2");
            assert_eq!(v2, b"value2".to_vec());

            assert_eq!(store.len(), 0);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }
}
