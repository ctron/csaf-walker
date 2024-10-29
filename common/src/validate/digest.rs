use crate::retrieve::RetrievedDigest;
use digest::Digest;

/// ensure that the digest matches if we have one
pub fn validate_digest<D: Digest>(
    digest: &Option<RetrievedDigest<D>>,
) -> Result<(), (String, String)> {
    if let Some(digest) = &digest {
        digest.validate().map_err(|(s1, s2)| (s1.to_string(), s2))?;
    }
    Ok(())
}
