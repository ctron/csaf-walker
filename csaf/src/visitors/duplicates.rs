use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use crate::report::{DocumentKey, Duplicates};
use std::sync::Arc;
use tokio::sync::Mutex;

/// An intercepting visitor, collecting duplicates
pub struct DetectDuplicatesVisitor<D: DiscoveredVisitor> {
    pub visitor: D,
    pub duplicates: Arc<Mutex<Duplicates>>,
}

impl<V: DiscoveredVisitor> DiscoveredVisitor for DetectDuplicatesVisitor<V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        {
            let key = DocumentKey::for_document(&advisory);

            let mut duplicates = self.duplicates.lock().await;
            if !duplicates.known.insert(key.clone()) {
                // add or get and increment by one
                *duplicates.duplicates.entry(key).or_default() += 1;
            }
        }

        self.visitor.visit_advisory(context, advisory).await
    }
}
