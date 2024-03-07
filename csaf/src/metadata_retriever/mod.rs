use crate::model::metadata::ProviderMetadata;
use crate::source::HttpSourceError;
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
}

impl From<Error> for HttpSourceError {
    fn from(value: Error) -> Self {
        match value {
            Error::Fetcher(err) => Self::Fetcher(err),
            Error::Url(err) => Self::Url(err),
            Error::SecurityTextError(err) => Self::SecurityTextError(err),
            Error::Json(err) => Self::Json(err),
        }
    }
}
pub struct MetadataRetriever {
    pub provider_metadata: ProviderMetadata,
}

impl MetadataRetriever {
    async fn get_url_from_security_text(fetcher: &Fetcher, host_url: Url) -> Result<String, Error> {
        let security_text = fetcher.fetch::<String>(host_url).await?;
        let text = SecurityTxt::parse(security_text.as_str())?;
        let url = text
            .extension
            .into_iter()
            .filter(|ext| ext.name == "csaf" && ext.value.contains("https"))
            .find(|_| true)
            .map(|ext| ext.value)
            .unwrap_or_else(|| "".to_string());

        Ok(url)
    }

    pub async fn retrieve_metadata(
        fetcher: &Fetcher,
        provider_metadata_url: Url,
    ) -> Result<Self, Error>
    where
        Self: Sized + Send,
    {
        let result = fetcher
            .fetch::<Json<ProviderMetadata>>(provider_metadata_url.clone())
            .await;

        match result {
            Ok(provider_metadata) => Ok(MetadataRetriever {
                provider_metadata: provider_metadata.into_inner(),
            }),
            Err(e) => {
                log::warn!(
                    "The url {:?} fetch failed {:?}",
                    provider_metadata_url.clone(),
                    e
                );
                log::trace!("Starting retrieve provider_metadata from DNS path ");
                if let Some(host_url) = provider_metadata_url.host_str() {
                    log::warn!("Querying provider metadata url DNS  {:?}", host_url);
                    let host_url_string = host_url.replace("www.", "");
                    let host_url_string =
                        format!("https://csaf.data.security.{}", &host_url_string);
                    let dns_path = Url::parse(host_url_string.as_str())?;

                    let dns_result = fetcher
                        .fetch::<Json<ProviderMetadata>>(dns_path.clone())
                        .await;
                    match dns_result {
                        Ok(provider_metadata) => Ok(MetadataRetriever {
                            provider_metadata: provider_metadata.into_inner(),
                        }),
                        Err(e) => {
                            log::warn!("DNS path {:?} fetch failed {:?}", dns_path.clone(), e);
                            let host_url_string = format!("https://{}", &host_url);
                            let host_url = Url::parse(host_url_string.as_str())?;
                            log::warn!(
                                "Querying provider metadata url from security text of {:?}",
                                host_url_string
                            );
                            let provider_metadata_url = Self::get_url_from_security_text(
                                fetcher,
                                host_url.join("/security.txt")?,
                            )
                            .await?;
                            let security_url = Url::parse(provider_metadata_url.as_str())?;
                            let security_result = fetcher
                                .fetch::<Json<ProviderMetadata>>(security_url.clone())
                                .await;

                            match security_result {
                                Ok(provider_metadata) => Ok(MetadataRetriever {
                                    provider_metadata: provider_metadata.into_inner(),
                                }),
                                Err(e) => {
                                    log::warn!(
                                        "security text url {} fetch failed {:?}",
                                        dns_path.clone().to_string(),
                                        e
                                    );
                                    let security_url = Self::get_url_from_security_text(
                                        fetcher,
                                        host_url.join("/.well-known/security.txt")?,
                                    )
                                    .await?;

                                    Ok(MetadataRetriever {
                                        provider_metadata: fetcher
                                            .fetch::<Json<ProviderMetadata>>(security_url.clone())
                                            .await?
                                            .into_inner(),
                                    })
                                }
                            }
                        }
                    }
                } else {
                    Err(Error::Url(ParseError::EmptyHost))
                }
            }
        }
    }
}
