use log::{error, info, warn};
use rust_proxy::{cache, tunnel};

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use inquire::{CustomType, Select, Text};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long, default_value_t = 8080)]
        control: u16,

        #[arg(short, long, default_value_t = 8081)]
        api_port: u16,

        #[arg(short, long)]
        password: Option<String>,

        #[arg(long)]
        admin_password: String,
    },
    Agent {
        #[arg(short, long)]
        connect: String,

        #[arg(short, long)]
        id: String,

        #[arg(short, long)]
        password: Option<String>,

        #[arg(long)]
        fingerprint: Option<String>,
    },
}

fn print_banner() {
    let banner = r#"
  ____            _   ____                                
 |  _ \ _   _ ___| |_|  _ \ _ __ _____  ___   _ 
 | |_) | | | / __| __| |_) | '__/ _ \ \/ / | | |
 |  _ <| |_| \__ \ |_|  __/| | | (_) >  <| |_| |
 |_| \_\\__,_|___/\__|_|   |_|  \___/_/\_\\__, |
                                          |___/ 
    "#;
    println!("{}", banner.bright_blue().bold());
    println!(
        "{}",
        " --- High Performance Reverse SOCKS5 Tunnel --- "
            .bright_black()
            .italic()
    );
    println!();
}

async fn run_interactive() -> Result<()> {
    print_banner();

    let options = vec!["Server (Public VPS)", "Agent (Home/Mobile/CGNAT)"];
    let choice = Select::new("Select Mode:", options).prompt()?;

    if choice == "Server (Public VPS)" {
        let control_port = CustomType::<u16>::new("Control Port:")
            .with_default(8080)
            .prompt()?;

        let agent_pw = Text::new("Agent Password (Optional, Enter for none):").prompt()?;
        let agent_pw = if agent_pw.is_empty() {
            None
        } else {
            Some(agent_pw)
        };
        let admin_pw = Text::new("Admin Password:").prompt()?;
        if admin_pw.is_empty() {
            anyhow::bail!("Admin password is required");
        }

        let registry = std::sync::Arc::new(dashmap::DashMap::new());
        let bind_registry = std::sync::Arc::new(dashmap::DashMap::new());
        run_server_with_cli(
            control_port,
            8081,
            agent_pw,
            admin_pw,
            registry,
            bind_registry,
        )
        .await
    } else {
        let agent_id = Text::new("Agent ID (e.g., Phone-1):").prompt()?;
        let server_ip = Text::new("Server IP/Host:").prompt()?;
        let control_port = CustomType::<u16>::new("Server Control Port:")
            .with_default(8080)
            .prompt()?;

        let server_pw = Text::new("Server Password (if required):").prompt()?;
        let s_pw = if server_pw.is_empty() {
            None
        } else {
            Some(server_pw)
        };

        let connect_addr = format!("{}:{}", server_ip, control_port);
        tunnel::run_agent(connect_addr, agent_id, s_pw, None).await
    }
}

async fn run_server_with_cli(
    control_port: u16,
    api_port: u16,
    agent_password: Option<String>,
    admin_password: String,
    registry: tunnel::AgentRegistry,
    bind_registry: tunnel::BindRegistry,
) -> Result<()> {
    let cache_mgr = Arc::new(cache::CacheManager::new("server_cache.json"));
    let initial_cache = cache_mgr.load().unwrap_or_default();

    let cumulative_usage = Arc::new(dashmap::DashMap::new());

    for agent in &initial_cache.agent_usage {
        cumulative_usage.insert(agent.agent_id.clone(), agent.cumulative_usage);
    }

    for b in initial_cache.binds {
        let (Some(user), Some(pass)) = (b.user.clone(), b.pass.clone()) else {
            error!(
                "Skipping cached SOCKS bind on port {}: missing user or password; refusing to restore an open proxy",
                b.port
            );
            continue;
        };
        let port = b.port;
        if !tunnel::is_socks_port(port) {
            warn!(
                "Skipping cached SOCKS bind on port {}: allowed range is {}-{}",
                port,
                tunnel::SOCKS_PORT_MIN,
                tunnel::SOCKS_PORT_MAX
            );
            continue;
        }
        let socks_listener = match tunnel::bind_socks_listener(port).await {
            Ok(listener) => listener,
            Err(e) => {
                warn!("Skipping cached SOCKS bind on port {}: {}", port, e);
                continue;
            }
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let id = b.agent_id.clone();

        let bind_usage = Arc::new(std::sync::atomic::AtomicU64::new(b.usage));
        bind_registry.insert(
            port,
            tunnel::BindEntry {
                agent_id: id.clone(),
                port,
                usage: bind_usage,
                max_conns: b.max_conns,
                connection_limit: Arc::new(tokio::sync::Semaphore::new(b.max_conns)),
                user: Some(user.clone()),
                pass: Some(pass.clone()),
                shutdown_tx: Some(shutdown_tx),
            },
        );

        let reg = Arc::clone(&registry);
        let b_reg = Arc::clone(&bind_registry);
        tokio::spawn(async move {
            if let Err(e) = tunnel::run_socks_listener(
                socks_listener,
                id,
                reg,
                b_reg,
                Some(user),
                Some(pass),
                shutdown_rx,
            )
            .await
            {
                log::error!("Restored SOCKS Listener failed on {}: {}", port, e);
            }
        });
    }

    let registry_for_server = Arc::clone(&registry);
    let bind_registry_for_server = Arc::clone(&bind_registry);
    let usage_for_server = Arc::clone(&cumulative_usage);
    tokio::spawn(async move {
        if let Err(e) = tunnel::run_server(
            control_port,
            api_port,
            agent_password,
            admin_password,
            registry_for_server,
            bind_registry_for_server,
            usage_for_server,
        )
        .await
        {
            log::error!("Background Server Failed: {}", e);
        }
    });

    let registry_for_save = Arc::clone(&registry);
    let bind_registry_for_save = Arc::clone(&bind_registry);
    let usage_for_save = Arc::clone(&cumulative_usage);
    let cache_mgr_for_save = Arc::clone(&cache_mgr);
    let (cache_stop_tx, mut cache_stop_rx) = tokio::sync::oneshot::channel();

    let cache_sync = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    if let Err(e) = save_server_cache(&cache_mgr_for_save, &registry_for_save, &bind_registry_for_save, &usage_for_save) {
                        log::error!("Failed to save cache: {}", e);
                    }
                }
                _ = &mut cache_stop_rx => break,
            }
        }
    });

    info!("Web GUI Dashboard active on http://127.0.0.1:{}", api_port);
    info!("Server running in background. Press Ctrl+C to exit.");
    if let Err(e) = wait_for_shutdown_signal().await {
        error!("Failed to listen for shutdown signal: {}", e);
    }
    info!("Shutting down...");
    let _ = cache_stop_tx.send(());
    let _ = cache_sync.await;
    if let Err(e) = save_server_cache(&cache_mgr, &registry, &bind_registry, &cumulative_usage) {
        error!("Failed to save cache during shutdown: {}", e);
    }

    Ok(())
}

fn save_server_cache(
    cache_mgr: &cache::CacheManager,
    registry: &tunnel::AgentRegistry,
    bind_registry: &tunnel::BindRegistry,
    cumulative_usage: &Arc<dashmap::DashMap<String, u64>>,
) -> Result<()> {
    let mut cache_data = cache::ServerCache::default();
    for entry in bind_registry.iter() {
        let b = entry.value();
        cache_data.binds.push(cache::BindConfig {
            port: *entry.key(),
            agent_id: b.agent_id.clone(),
            user: b.user.clone(),
            pass: b.pass.clone(),
            usage: b.usage.load(Ordering::Relaxed),
            max_conns: b.max_conns,
        });
    }

    let mut agent_usage = BTreeMap::new();
    for entry in cumulative_usage.iter() {
        agent_usage.insert(entry.key().clone(), *entry.value());
    }
    for entry in registry.iter() {
        agent_usage
            .entry(entry.key().clone())
            .and_modify(|usage| *usage = (*usage).max(entry.value().usage.load(Ordering::Relaxed)))
            .or_insert_with(|| entry.value().usage.load(Ordering::Relaxed));
    }
    cache_data.agent_usage = agent_usage
        .into_iter()
        .map(|(agent_id, cumulative_usage)| cache::AgentCache {
            agent_id,
            cumulative_usage,
        })
        .collect();
    cache_mgr.save(&cache_data)
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Server {
            control,
            api_port,
            password,
            admin_password,
        }) => {
            print_banner();
            info!("Running in SERVER mode");
            let registry = std::sync::Arc::new(dashmap::DashMap::new());
            let bind_registry = std::sync::Arc::new(dashmap::DashMap::new());
            run_server_with_cli(
                control,
                api_port,
                password,
                admin_password,
                registry,
                bind_registry,
            )
            .await?;
        }
        Some(Commands::Agent {
            connect,
            id,
            password,
            fingerprint,
        }) => {
            print_banner();
            info!("Running in AGENT mode ('{}')", id);
            if let Some(fingerprint) = fingerprint {
                tunnel::run_agent_with_fingerprint(connect, id, password, fingerprint, None)
                    .await?;
            } else {
                tunnel::run_agent(connect, id, password, None).await?;
            }
        }
        None => {
            run_interactive().await?;
        }
    }
    Ok(())
}
