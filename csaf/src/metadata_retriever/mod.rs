use crate::model::metadata::ProviderMetadata;
use crate::source::{HttpSourceError, WELL_KNOWN_METADATA};
use sectxtlib::SecurityTxt;
use url::{ParseError, Url};
use walker_common::fetcher;
use walker_common::fetcher::{Fetcher, Json};

type Error = HttpSourceError;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectionType {
    WellKnowPath(ProviderMetadata),
    DnsPath(ProviderMetadata),
    SecurityTextPath(ProviderMetadata),
}

#[derive(Clone)]
pub struct MetadataRetriever {
    pub base_url: String,
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

            Ok(url)
        } else {
            Ok(None)
        }
    }

    pub async fn fetch_metadata_from_url(
        &self,
        provider_metadata_url: Url,
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        let metadata = self
            .fetcher
            .fetch::<Option<Json<ProviderMetadata>>>(provider_metadata_url)
            .await?;
        Ok(metadata)
    }

    /// Retrieve provider metadata through the full well known URL.
    pub async fn retrieve_metadata_by_well_known_url(
        &self,
        provider_metadata_url: Url,
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        log::trace!("Starting retrieve provider metadata from full provided discovery URL");
        match provider_metadata_url.host_str() {
            None => Err(Error::Url(ParseError::EmptyHost)),
            Some(host_url) => {
                let url =
                    Url::parse(format!("https://{}/{}", host_url, WELL_KNOWN_METADATA).as_str())?;
                self.fetch_metadata_from_url(url).await
            }
        }
    }

    /// Retrieve provider metadata through the DNS path of provided URL.
    pub async fn retrieve_metadata_by_dns(
        &self,
        provider_metadata_url: Url,
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        log::trace!("Starting retrieve provider_metadata from DNS path of provided discovery URL ");
        if let Some(host_url) = provider_metadata_url.host_str() {
            log::info!("Querying provider metadata url DNS  {:?}", host_url);
            let host_url_string = format!("https://csaf.data.security.{}", host_url);
            let dns_path = Url::parse(host_url_string.as_str())?;

            match self.fetch_metadata_from_url(dns_path).await {
                Ok(provider_metadata) => Ok(provider_metadata),
                Err(err) => match err {
                    Error::Fetcher(fetch_error) => match fetch_error {
                        fetcher::Error::Request(reqwest_error) => {
                            if reqwest_error.is_connect() {
                                log::warn!("When DNS path URL {} fetch provider metadata fails due to a fetch error, which is a DNS error, the process will proceed to the next discovery rule. {:?}", provider_metadata_url.clone().to_string(), reqwest_error,);
                                Ok(None)
                            } else {
                                Err(Error::Fetcher(fetcher::Error::Request(reqwest_error)))
                            }
                        }
                    },
                    _ => Err(err),
                },
            }
        } else {
            Err(Error::Url(ParseError::EmptyHost))
        }
    }

    /// Retrieve provider metadata through the security text of provided URL.
    pub async fn retrieve_metadata_by_security_text(
        &self,
        provider_metadata_url: Url,
        security_txt_path: &str,
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        log::trace!(
            "Starting retrieve provider metadata from security text of provided discovery URL "
        );
        if let Some(host_url) = provider_metadata_url.clone().host_str() {
            let host_url_string = format!("https://{}", &host_url);
            let host_url = Url::parse(host_url_string.as_str())?;
            log::info!(
                "Querying provider metadata url from security text of {:?}",
                host_url_string
            );
            if let Some(path) = Self::get_metadata_url_from_security_text(
                &self.fetcher,
                host_url.join(security_txt_path)?,
            )
            .await?
            {
                let provider_metadata_url = Url::parse(path.as_str())?;

                Ok(self.fetch_metadata_from_url(provider_metadata_url).await?)
            } else {
                log::warn!(
                    "The Security Text obtained from this URL is 'None': {} ",
                    host_url_string
                );
                Ok(None)
            }
        } else {
            Err(Error::Url(ParseError::EmptyHost))
        }
    }

    ///For the provided metadata URL, retrieve the provider metadata using three different discovery methods in a specified order.
    pub async fn retrieve(&self) -> Result<DetectionType, Error> {
        let actually_url = if self.base_url.clone().starts_with("https://") {
            Url::parse(&self.base_url)?
        } else {
            Url::parse(&format!("https://{}", self.base_url.clone()))?
        };

        if let Some(provider_metadata) = self
            .retrieve_metadata_by_well_known_url(actually_url.clone())
            .await?
        {
            return Ok(DetectionType::WellKnowPath(provider_metadata.into_inner()));
        } else {
            log::warn!(
                    "The provider metadata obtained from this well known URL is 'None': {}，the process will proceed to the next discovery rule.",
                    self.base_url.clone().to_string(),
                );
        }

        // If the first method (full well-known URL) fails, attempt again using the DNS path method.
        if let Some(provider_metadata) = self.retrieve_metadata_by_dns(actually_url.clone()).await?
        {
            return Ok(DetectionType::DnsPath(
                provider_metadata.clone().into_inner(),
            ));
        } else {
            log::warn!(
                "The provider metadata obtained from this DNS path URL is 'None': {}",
                self.base_url.clone().to_string(),
            );
        }

        // If the second method (dns path) fails, attempt again using the short security text method
        if let Some(provider_metadata) = self
            .retrieve_metadata_by_security_text(actually_url.clone(), "/security.txt")
            .await?
        {
            return Ok(DetectionType::SecurityTextPath(
                provider_metadata.clone().into_inner(),
            ));
        } else {
            log::warn!(
                "The provider metadata obtained from this security text URL is 'None': {}",
                self.base_url.clone().to_string(),
            );
        }

        // If the third method (short security text) fails, attempt again using the full security text method.
        if let Some(provider_metadata) = self
            .retrieve_metadata_by_security_text(actually_url.clone(), "/.well-known/security.txt")
            .await?
        {
            return Ok(DetectionType::SecurityTextPath(
                provider_metadata.clone().into_inner(),
            ));
        }

        Err(Error::EmptyProviderMetadata(self.base_url.to_string()))
    }
}
