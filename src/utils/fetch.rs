use reqwest::{IntoUrl, StatusCode};

pub async fn fetch_string_optional(
    client: &reqwest::Client,
    url: impl IntoUrl,
) -> Result<Option<String>, reqwest::Error> {
    let response = client.get(url).send().await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    Ok(Some(response.error_for_status()?.text().await?))
}
