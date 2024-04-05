
use std::collections::HashMap;
use crate::oauth2_provider::OAuth2Provider;

pub struct Oauth2Manager {
    providers: HashMap<String, Box<dyn OAuth2Provider>>,
}

impl Oauth2Manager {
    pub fn new(_key: String) -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    // Registers a new provider with the manager.
    pub fn add_provider<P: OAuth2Provider + Send + Sync + 'static>(
        &mut self,
        name: String,
        provider: P,
    ) {
        self.providers.insert(name, Box::new(provider));
    }

    // Finds and returns the provider based on the name.
    pub fn get_provider(&self, name: &str) -> Option<&(dyn OAuth2Provider)> {
        self.providers.get(name).map(|p| p.as_ref())
    }
}