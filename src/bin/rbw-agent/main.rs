use anyhow::Context as _;
use tokio::signal::unix::{signal, SignalKind};

mod agent;
mod daemon;
mod debugger;
mod notifications;
mod sock;

async fn async_main(startup_ack: Option<crate::daemon::StartupAck>) -> anyhow::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = rbw::config::Config::load()?;

    let agent = crate::agent::Agent::new(config).await;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select!(
        _ = agent.run(listener) => {},
        _ = sigint.recv() => {
            log::warn!("SIGINT received. Closing the application.");
        },
        _ = sigterm.recv() => {
            log::warn!("SIGTERM received. Closing the application.");
        }
    );

    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let no_daemonize = std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--no-daemonize");

    rbw::dirs::make_all()?;

    let startup_ack = daemon::daemonize(no_daemonize).context("failed to daemonize")?;

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    tokio::runtime::Runtime::new()?.block_on(async { async_main(startup_ack).await })?;

    Ok(())
}
