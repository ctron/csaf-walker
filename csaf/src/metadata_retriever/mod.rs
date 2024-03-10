use crate::model::metadata::ProviderMetadata;
use crate::source::{HttpSourceError, MetadataLookupError};
use sectxtlib::SecurityTxt;
use url::{ParseError, Url};
use walker_common::fetcher;
use walker_common::fetcher::{Fetcher, Json};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Fetch error: {0}")]
    Fetcher(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("securityTxtParseError error: {0}")]
    SecurityTextError(#[from] sectxtlib::ParseError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Metadata lookup error: {0}")]
    MetadataLookup(#[from] MetadataLookupError),
}

impl From<Error> for HttpSourceError {
    fn from(value: Error) -> Self {
        match value {
            Error::Fetcher(err) => Self::Fetcher(err),
            Error::Url(err) => Self::Url(err),
            Error::SecurityTextError(err) => Self::SecurityTextError(err),
            Error::Json(err) => Self::Json(err),
            Error::MetadataLookup(err) => Self::MetadataLookup(err),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectionType {
    WellKnowPath(ProviderMetadata),
    DnsPath(ProviderMetadata),
    SecurityTextPath(ProviderMetadata),
}

#[derive(Clone)]
pub struct MetadataRetriever {
    pub provider_metadata_url: Url,
    pub fetcher: Fetcher,
}

impl MetadataRetriever {
    pub async fn get_metadata_url_from_security_text(
        fetcher: &Fetcher,
        host_url: Url,
    ) -> Result<Option<String>, Error> {
        let security_text = fetcher.fetch::<Option<String>>(host_url.clone()).await?;

        if let Some(text) = security_text {
            let text = SecurityTxt::parse(&text)?;
            let url = text
                .extension
                .into_iter()
                .filter(|ext| ext.name == "csaf" && ext.value.contains("https"))
                .find(|_| true)
                .map(|ext| ext.value);

            return Ok(url);
        }
        Err(Error::MetadataLookup(
            MetadataLookupError::EmptySecurityText(host_url.clone().to_string()),
        ))
    }

    async fn fetch_metadata_from_url(
        fetcher: &Fetcher,
        provider_metadata_url: Url,
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        let metadata = fetcher
            .fetch::<Option<Json<ProviderMetadata>>>(provider_metadata_url.clone())
            .await?;
        Ok(metadata)
    }

    /// Retrieve provider metadata through the full well known URL.
    pub async fn retrieve_metadata_by_well_known_url(
        &self,
    ) -> Result<Option<Json<ProviderMetadata>>, Error>
    where
        Self: Sized + Send,
    {
        log::trace!("Starting retrieve provider metadata from full provided discovery URL");
        Self::fetch_metadata_from_url(&self.fetcher, self.provider_metadata_url.clone()).await
    }

    /// Retrieve provider metadata through the DNS path of provided URL.
    pub async fn retrieve_metadata_by_dns(&self) -> Result<Option<Json<ProviderMetadata>>, Error>
    where
        Self: Sized + Send,
    {
        log::trace!("Starting retrieve provider_metadata from DNS path of provided discovery URL ");
        if let Some(host_url) = self.provider_metadata_url.clone().host_str() {
            log::info!("Querying provider metadata url DNS  {:?}", host_url);
            let host_url_string = host_url.replace("www.", "");
            let host_url_string = format!("https://csaf.data.security.{}", &host_url_string);
            let dns_path = Url::parse(host_url_string.as_str())?;

            Ok(Self::fetch_metadata_from_url(&self.fetcher, dns_path.clone()).await?)
        } else {
            Err(Error::Url(ParseError::EmptyHost))
        }
    }

    /// Retrieve provider metadata through the security text of provided URL.
    pub async fn retrieve_metadata_by_security_text(
        &self,
        security_txt_path: &str,
    ) -> Result<Option<Json<ProviderMetadata>>, Error>
    where
        Self: Sized + Send,
    {
        log::trace!(
            "Starting retrieve provider metadata from security text of provided discovery URL "
        );
        if let Some(host_url) = self.provider_metadata_url.clone().host_str() {
            let host_url_string = format!("https://{}", &host_url);
            let host_url = Url::parse(host_url_string.as_str())?;
            log::info!(
                "Querying provider metadata url from security text of {:?}",
                host_url_string
            );
            let provider_metadata_path = Self::get_metadata_url_from_security_text(
                &self.fetcher,
                host_url.join(security_txt_path)?,
            )
            .await?;
            match provider_metadata_path {
                None => Err(Error::MetadataLookup(MetadataLookupError::CsafNotExist(
                    host_url_string,
                ))),
                Some(provider_metadata_path) => {
                    let provider_metadata_url = Url::parse(provider_metadata_path.as_str())?;

                    Ok(
                        Self::fetch_metadata_from_url(&self.fetcher, provider_metadata_url.clone())
                            .await?,
                    )
                }
            }
        } else {
            Err(Error::Url(ParseError::EmptyHost))
        }
    }

    ///For the provided metadata URL, retrieve the provider metadata using three different discovery methods in a specified order.
    pub async fn retrieve(self) -> Result<DetectionType, Error>
    where
        Self: Sized + Send,
    {
        let well_known_result = self.retrieve_metadata_by_well_known_url().await;
        if let Ok(provider_metadata) = &well_known_result {
            if let Some(metadata) = provider_metadata {
                return Ok(DetectionType::WellKnowPath(metadata.clone().into_inner()));
            } else {
                log::warn!(
                    "The provider metadata obtained from this well known URL is 'None': {}",
                    self.provider_metadata_url.clone().to_string(),
                );
            }
        }
        if let Err(err) = &well_known_result {
            log::warn!(
                "The provided discovery URL {} fetch provider metadata failed: {:?}",
                self.provider_metadata_url.clone().to_string(),
                err
            );
        }

        // If the first method (full well-known URL) fails, attempt again using the DNS path method.
        let dns_result = self.retrieve_metadata_by_dns().await;
        if let Ok(provider_metadata) = &dns_result {
            if let Some(metadata) = provider_metadata {
                return Ok(DetectionType::DnsPath(metadata.clone().into_inner()));
            } else {
                log::warn!(
                    "The provider metadata obtained from this DNS path URL is 'None': {}",
                    self.provider_metadata_url.clone().to_string(),
                );
            }
        }

        if let Err(err) = &dns_result {
            log::warn!(
                "The DNS path URL {} fetch provider metadata failed : {:?}",
                self.provider_metadata_url.to_string(),
                err
            );
        }

        // If the second method (dns path) fails, attempt again using the short security text method
        let security_result = self
            .retrieve_metadata_by_security_text("/security.txt")
            .await;
        if let Ok(provider_metadata) = &security_result {
            if let Some(metadata) = provider_metadata {
                return Ok(DetectionType::SecurityTextPath(
                    metadata.clone().into_inner(),
                ));
            } else {
                log::warn!(
                    "The provider metadata obtained from this security text URL is 'None': {}",
                    self.provider_metadata_url.clone().to_string(),
                );
            }
        }

        if let Err(err) = &dns_result {
            log::warn!(
                "The security text URL {} fetch provider metadata failed : {:?}",
                self.provider_metadata_url.clone().to_string(),
                err
            );
        }

        // If the third method (short security text) fails, attempt again using the full security text method.
        let full_path_security_result = self
            .retrieve_metadata_by_security_text("/.well-known/security.txt")
            .await;

        if let Ok(provider_metadata) = &full_path_security_result {
            if let Some(metadata) = provider_metadata {
                return Ok(DetectionType::SecurityTextPath(
                    metadata.clone().into_inner(),
                ));
            } else {
                log::warn!(
                    "The provider metadata obtained from this full security text URL is 'None': {}",
                    self.provider_metadata_url.clone().to_string(),
                );
            }
        }

        if let Err(err) = &full_path_security_result {
            log::warn!(
                "The full security text URL {} fetch provider metadata failed : {:?}",
                self.provider_metadata_url.clone().to_string(),
                err
            );
        }

        Err(Error::MetadataLookup(
            MetadataLookupError::EmptyProviderMetadata(self.provider_metadata_url.to_string()),
        ))
    }
}
