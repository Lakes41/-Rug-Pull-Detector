use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct CpuPool {
    pool: Arc<rayon::ThreadPool>,
}

impl CpuPool {
    pub fn new(threads: usize) -> Self {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("rayon-cpu-{}", i))
            .build()
            .expect("Failed to initialize Rayon CPU thread pool");
        Self { pool: Arc::new(pool) }
    }

    /// Spawns a CPU-heavy closure onto the Rayon pool and returns a Future
    pub async fn spawn<F, R>(&self, f: F) -> Result<R, tokio::sync::oneshot::error::RecvError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.pool.spawn(move || {
            let res = f();
            let _ = tx.send(res);
        });
        rx.await
    }
}
