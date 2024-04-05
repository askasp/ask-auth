
use std::collections::HashMap;
use crate::oauth2_provider::Oauth2Provider;

pub struct Oauth2Manager {
    providers: HashMap<String, Box<dyn Oauth2Provider>>,
}

impl Oauth2Manager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    // Registers a new provider with the manager.
    pub fn add_provider<P: Oauth2Provider + Send + Sync + 'static>(
        &mut self,
        name: String,
        provider: P,
    ) {
        self.providers.insert(name, Box::new(provider));
    }
    pub fn get_providers(&self) -> &HashMap<String, Box<dyn Oauth2Provider>> {
        &self.providers
    }

    // Finds and returns the provider based on the name.
    pub fn get_provider(&self, name: &str) -> Option<&(dyn Oauth2Provider)> {
        self.providers.get(name).map(|p| p.as_ref())
    }
}