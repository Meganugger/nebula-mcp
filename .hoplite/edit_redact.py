import re

p = 'crates/core/src/config.rs'
s = open(p).read()
s = s.replace('''    /// Serialise this config to TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self)
            .map_err(|e| ConfigError::new(format!("serialising configuration: {e}")))
    }
''', '''    /// Serialise this config to TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self)
            .map_err(|e| ConfigError::new(format!("serialising configuration: {e}")))
    }

    /// This configuration as TOML with every secret replaced, fit to show to
    /// an operator or a client.
    pub fn to_redacted_toml(&self) -> Result<String, ConfigError> {
        let mut copy = self.clone();
        for token in &mut copy.transport.http.auth_tokens {
            *token = "<redacted>".to_string();
        }
        if let Some(secret) = &mut copy.transport.http.oauth.approval_secret {
            *secret = "<redacted>".to_string();
        }
        copy.to_toml_string()
    }
''', 1)
open(p, 'w').write(s)

p = 'crates/server/src/cli.rs'
s = open(p).read()
a = s.index('/// The configuration as TOML with every secret replaced.')
b = s.index('fn list_tools(', a)
s = s[:a] + '''/// The configuration as TOML with every secret replaced.
fn redacted(config: &Config) -> Result<String, String> {
    config.to_redacted_toml().map_err(|e| e.to_string())
}

''' + s[b:]
open(p, 'w').write(s)
