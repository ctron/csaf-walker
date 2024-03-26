use crate::model::metadata::ProviderMetadata;
use crate::source::{HttpSourceError, WELL_KNOWN_METADATA};
use sectxtlib::SecurityTxt;
use walker_common::fetcher;
use walker_common::fetcher::{Fetcher, Json};

type Error = HttpSourceError;

#[derive(Clone)]
pub struct MetadataRetriever {
    pub base_url: String,
    pub fetcher: Fetcher,
}

impl MetadataRetriever {
    pub async fn get_metadata_url_from_security_text(
        fetcher: &Fetcher,
        host_url: String,
    ) -> Result<Option<String>, Error> {
        let security_text = fetcher.fetch::<Option<String>>(host_url).await?;

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
        provider_metadata_url: String,
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
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        log::trace!("Starting retrieve provider metadata from full provided discovery URL");
        let url = format!("https://{}/{}", self.base_url, WELL_KNOWN_METADATA);
        self.fetch_metadata_from_url(url).await
    }

    /// Retrieve provider metadata through the DNS path of provided URL.
    pub async fn retrieve_metadata_by_dns(&self) -> Result<Option<Json<ProviderMetadata>>, Error> {
        log::trace!("Starting retrieve provider_metadata from DNS path of provided discovery URL ");
        let url = format!("https://csaf.data.security.{}", self.base_url);
        match self.fetch_metadata_from_url(url.clone()).await {
            Ok(provider_metadata) => Ok(provider_metadata),
            Err(err) => match err {
                Error::Fetcher(fetch_error) => match fetch_error {
                    fetcher::Error::Request(reqwest_error) => {
                        if reqwest_error.is_connect() {
                            log::info!("When DNS path URL {} fetch provider metadata fails due to a fetch error, which is a DNS error, the process will proceed to the next discovery rule. {:?}", url.clone(), reqwest_error,);
                            Ok(None)
                        } else {
                            Err(Error::Fetcher(fetcher::Error::Request(reqwest_error)))
                        }
                    }
                },
                _ => Err(err),
            },
        }
    }

    /// Retrieve provider metadata through the security text of provided URL.
    pub async fn retrieve_metadata_by_security_text(
        &self,
        security_txt_path: &str,
    ) -> Result<Option<Json<ProviderMetadata>>, Error> {
        log::trace!(
            "Starting retrieve provider metadata from security text of provided discovery URL "
        );
        let security_text_url = format!("https://{}/{}", self.base_url, security_txt_path);

        if let Some(path) =
            Self::get_metadata_url_from_security_text(&self.fetcher, security_text_url.clone())
                .await?
        {
            Ok(self.fetch_metadata_from_url(path).await?)
        } else {
            log::info!(
                "The Security Text obtained from this URL is 'None': {} ",
                security_text_url
            );
            Ok(None)
        }
    }

    ///For the provided metadata URL, retrieve the provider metadata using three different discovery methods in a specified order.
    pub async fn retrieve(&self) -> Result<ProviderMetadata, Error> {
        if self.base_url.clone().starts_with("https://") {
            if let Some(provider_metadata) =
                self.fetch_metadata_from_url(self.base_url.clone()).await?
            {
                return Ok(provider_metadata.into_inner());
            } else {
                return Err(Error::EmptyProviderMetadata(self.base_url.to_string()));
            }
        }

        if let Some(provider_metadata) = self.retrieve_metadata_by_well_known_url().await? {
            return Ok(provider_metadata.into_inner());
        } else {
            log::info!(
                    "The provider metadata obtained from this well known URL is 'None': {}，the process will proceed to the next discovery rule.",
                    self.base_url.clone(),
                );
        }

        // If the first method (full well-known URL) fails, attempt again using the DNS path method.
        if let Some(provider_metadata) = self.retrieve_metadata_by_dns().await? {
            return Ok(provider_metadata.into_inner());
        } else {
            log::info!(
                "The provider metadata obtained from this DNS path URL is 'None': {}",
                self.base_url.clone(),
            );
        }

        // If the second method (dns path) fails, attempt again using the short security text method
        if let Some(provider_metadata) = self
            .retrieve_metadata_by_security_text("/security.txt")
            .await?
        {
            return Ok(provider_metadata.into_inner());
        } else {
            log::info!(
                "The provider metadata obtained from this security text URL is 'None': {}",
                self.base_url.clone(),
            );
        }

        // If the third method (short security text) fails, attempt again using the full security text method.
        if let Some(provider_metadata) = self
            .retrieve_metadata_by_security_text("/.well-known/security.txt")
            .await?
        {
            return Ok(provider_metadata.into_inner());
        }

        Err(Error::EmptyProviderMetadata(self.base_url.to_string()))
    }
}
