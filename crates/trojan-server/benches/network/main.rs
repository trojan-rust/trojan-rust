//! Real socket measurements. The relay runs in a separate process from the load generator.

mod fixture;
mod load;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::watch;
use tokio::task::JoinSet;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Tls,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, value_delimiter = ',', default_value = "tcp,tls")]
    transports: Vec<Transport>,
    #[arg(long, value_delimiter = ',', default_value = "1,32,128")]
    connections: Vec<usize>,
    #[arg(long, default_value_t = 3)]
    seconds: u64,
    #[arg(long, default_value_t = 3)]
    repeats: usize,
    #[arg(long, default_value_t = 4)]
    workers: usize,
    #[arg(long, default_value_t = 512)]
    latency_bytes: usize,
    #[arg(long, default_value_t = 32768)]
    bulk_bytes: usize,
    #[arg(long, default_value_t = 32768)]
    buffer_bytes: usize,
    #[arg(long, default_value = "unlabelled")]
    label: String,
    #[arg(long, hide = true)]
    serve: Option<PathBuf>,
    // Cargo passes this flag to custom benchmark executables.
    #[arg(long, hide = true)]
    bench: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.workers == 0
        || args.seconds == 0
        || args.repeats == 0
        || args.connections.contains(&0)
        || args.latency_bytes == 0
        || args.bulk_bytes == 0
    {
        return Err(
            io::Error::other("counts, durations, and payload sizes must be positive").into(),
        );
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| io::Error::other("crypto provider already installed"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.workers)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        if let Some(path) = &args.serve {
            return fixture::serve(path).await;
        }
        println!(
            "{}",
            json!({
                "kind": "environment", "label": args.label,
                "os": System::long_os_version(), "arch": std::env::consts::ARCH,
                "logical_cpus": std::thread::available_parallelism()?.get(),
                "workers_per_process": args.workers, "seconds_per_phase": args.seconds,
                "latency_bytes": args.latency_bytes, "bulk_bytes": args.bulk_bytes,
                "relay_buffer_bytes": args.buffer_bytes,
                "cpu_percent_scale": "100 = one fully occupied CPU",
            })
        );
        for repeat in 1..=args.repeats {
            for &connections in &args.connections {
                for &transport in &args.transports {
                    measure(&args, transport, connections, repeat).await?;
                }
            }
        }
        Ok(())
    })
}

async fn measure(
    args: &Args,
    transport: Transport,
    connections: usize,
    repeat: usize,
) -> Result<()> {
    let mut fixture = fixture::Fixture::start(args, transport).await?;
    let mut resources = Resources::new(fixture.pid());
    let idle = resources.read()?;

    let mut connecting = JoinSet::new();
    for _ in 0..connections {
        let endpoint = fixture.endpoint.clone();
        let warmup_bytes = args.buffer_bytes;
        connecting.spawn(async move {
            let mut stream = endpoint.connect().await?;
            // Touch relay buffers before measuring resident memory or steady-state I/O.
            load::warmup(&mut stream, warmup_bytes).await?;
            Ok::<_, Error>(stream)
        });
    }
    let mut streams = Vec::with_capacity(connections);
    while let Some(result) = connecting.join_next().await {
        streams.push(result??);
    }
    let connected = resources.read()?;
    let duration = Duration::from_secs(args.seconds);

    let (start, signal) = watch::channel(None);
    let payload = Arc::new(vec![0x5a; args.latency_bytes]);
    let mut latency_tasks = JoinSet::new();
    for stream in streams {
        latency_tasks.spawn(load::latency(stream, payload.clone(), signal.clone()));
    }
    let before = resources.read()?;
    let began = Instant::now();
    start.send(Some(began + duration))?;
    let mut latencies = Vec::new();
    let mut streams = Vec::with_capacity(connections);
    while let Some(result) = latency_tasks.join_next().await {
        let (stream, samples) = result??;
        streams.push(stream);
        latencies.extend(samples);
    }
    let latency_elapsed = began.elapsed().as_secs_f64();
    let latency_resources = resources.read()?;
    if latencies.is_empty() {
        return Err(io::Error::other("latency phase completed without samples").into());
    }
    latencies.sort_unstable();
    let p99 = latencies[(latencies.len() * 99).div_ceil(100) - 1];
    let latency_cpu = cpu_percent(before, latency_resources, latency_elapsed);

    let (start, signal) = watch::channel(None);
    let payload = Arc::new(vec![0xa5; args.bulk_bytes]);
    let mut bulk_tasks = JoinSet::new();
    for stream in streams {
        bulk_tasks.spawn(load::bulk(stream, payload.clone(), signal.clone()));
    }
    let before = resources.read()?;
    let began = Instant::now();
    start.send(Some(began + duration))?;
    let mut total_bytes = 0u64;
    let mut peak_rss = latency_resources.rss;
    let mut sample = tokio::time::interval(Duration::from_millis(200));
    while !bulk_tasks.is_empty() {
        tokio::select! {
            result = bulk_tasks.join_next() => {
                total_bytes += result.expect("bulk task exists")??;
            }
            _ = sample.tick() => {
                peak_rss = peak_rss.max(resources.read()?.rss);
            }
        }
    }
    let bulk_elapsed = began.elapsed().as_secs_f64();
    let after = resources.read()?;
    println!(
        "{}",
        json!({
            "kind": "measurement", "label": args.label, "transport": transport,
            "connections": connections, "repeat": repeat,
            "latency": {
                "requests": latencies.len(), "elapsed_secs": latency_elapsed,
                "requests_per_sec": latencies.len() as f64 / latency_elapsed,
                "p50_us": latencies[latencies.len() / 2] as f64 / 1000.0,
                "p99_us": p99 as f64 / 1000.0,
                "server_cpu_percent": latency_cpu,
            },
            "bulk": {
                "echoed_bytes": total_bytes, "elapsed_secs": bulk_elapsed,
                "round_trip_mib_per_sec": total_bytes as f64 * 2.0 / 1048576.0 / bulk_elapsed,
                "server_cpu_percent": cpu_percent(before, after, bulk_elapsed),
                "server_peak_rss_bytes": peak_rss.max(after.rss),
            },
            "memory": {
                "server_idle_rss_bytes": idle.rss,
                "server_connected_rss_bytes": connected.rss,
                "rss_delta_bytes_per_connection":
                    (connected.rss as f64 - idle.rss as f64) / connections as f64,
            },
        })
    );
    fixture.stop()?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Snapshot {
    cpu_ms: u64,
    rss: u64,
}

struct Resources {
    system: System,
    pid: Pid,
}

impl Resources {
    fn new(pid: u32) -> Self {
        Self {
            system: System::new(),
            pid: Pid::from_u32(pid),
        }
    }

    fn read(&mut self) -> Result<Snapshot> {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        let process = self
            .system
            .process(self.pid)
            .ok_or_else(|| io::Error::other("server process is unavailable"))?;
        if process.memory() == 0 {
            return Err(io::Error::other("server RSS is unavailable on this platform").into());
        }
        Ok(Snapshot {
            cpu_ms: process.accumulated_cpu_time(),
            rss: process.memory(),
        })
    }
}

fn cpu_percent(before: Snapshot, after: Snapshot, elapsed: f64) -> f64 {
    (after.cpu_ms - before.cpu_ms) as f64 / 10.0 / elapsed
}
