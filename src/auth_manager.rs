use crate::{auth_provider::AuthProvider};
use std::collections::HashMap;

pub struct AuthProviderManager {
    providers: HashMap<String, AuthProvider>,
}

impl AuthProviderManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    // Registers a new provider with the manager.
    pub fn add_provider(&mut self, name: String, provider: AuthProvider) {
        self.providers.insert(name, provider);
    }
    pub fn get_providers(&self) -> &HashMap<String, AuthProvider> {
        &self.providers
    }

    // Finds and returns the provider based on the name.
    pub fn get_provider(&self, name: &str) -> Option<&AuthProvider> {
        self.providers.get(name)
    }
}
