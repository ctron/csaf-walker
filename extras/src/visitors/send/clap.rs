use crate::visitors::SendVisitor;
use reqwest::Url;
use std::path::PathBuf;
use walker_common::sender::{self, provider::OpenIdTokenProviderConfigArguments, HttpSender};

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Sending")]
pub struct SendArguments {
    /// Target to send to
    pub target: Url,

    /// Sender connect timeout
    #[arg(id = "sender-connect-timeout", long, default_value = "15s")]
    pub connect_timeout: humantime::Duration,

    /// Sender request timeout
    #[arg(id = "sender-timeout", long, default_value = "5m")]
    pub timeout: humantime::Duration,

    /// Additional root certificates
    #[arg(id = "sender-root-certificate", long)]
    pub additional_root_certificates: Vec<PathBuf>,

    /// Number of retries in case of temporary failures
    #[arg(id = "sender-retries", long, default_value = "0")]
    pub retries: usize,

    /// Delay between retries
    #[arg(id = "sender-retry-delay", long, default_value = "5s")]
    pub retry_delay: humantime::Duration,

    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,
}

impl SendArguments {
    pub async fn into_visitor(self) -> Result<SendVisitor, anyhow::Error> {
        let provider = self.oidc.into_provider().await?;
        let sender = HttpSender::new(
            provider,
            sender::Options::default()
                .connect_timeout(self.connect_timeout)
                .timeout(self.timeout)
                .additional_root_certificates(self.additional_root_certificates),
        )
        .await?;

        Ok(SendVisitor {
            url: self.target,
            sender,
            retries: self.retries,
            retry_delay: Some(self.retry_delay.into()),
        })
    }
}
