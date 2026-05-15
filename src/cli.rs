use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "profile-vault")]
#[command(author = "momoyash")]
#[command(version = "0.2.0")]
#[command(about = "Password-protect browser profiles with real encryption", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all browser profiles and their lock status
    List {
        /// Filter by browser (chrome, edge, firefox, brave)
        #[arg(short, long)]
        browser: Option<String>,
    },

    /// Lock a browser profile with a password
    Lock {
        /// Browser name (chrome, edge, firefox, brave)
        browser: String,

        /// Profile ID (e.g., "Default", "Profile 1")
        profile: String,

        /// Password (if not provided, will prompt interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Skip generating a recovery phrase. Strongly discouraged: without
        /// a recovery phrase a forgotten password = permanent data loss.
        #[arg(long)]
        no_recovery: bool,
    },

    /// Unlock a locked browser profile
    Unlock {
        /// Browser name (chrome, edge, firefox, brave)
        browser: String,

        /// Profile ID (e.g., "Default", "Profile 1")
        profile: String,

        /// Password (if not provided, will prompt interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Unlock using the recovery phrase instead of the password.
        #[arg(long)]
        recovery: bool,

        /// Launch browser after unlocking
        #[arg(short, long)]
        launch: bool,

        /// Auto-lock when browser closes (implies --launch)
        #[arg(short, long)]
        auto_lock: bool,
    },

    /// Show status of locked profiles
    Status,

    /// List supported browsers
    Browsers,
}
