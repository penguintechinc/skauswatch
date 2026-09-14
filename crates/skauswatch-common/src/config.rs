//! Environment-driven configuration loading via figment.
//! All services load typed config structs from prefixed env vars, matching
//! the PenguinTech env-var conventions (DB_*, CACHE_*, LICENSE_*, ...).

use figment::Figment;
use figment::providers::Env;
use serde::de::DeserializeOwned;

use crate::error::Error;

/// Loads a typed configuration struct from environment variables with the
/// given prefix (e.g. `load_config::<DbConfig>("DB_")` reads `DB_HOST`, ...).
/// Field names map case-insensitively to the suffix after the prefix.
pub fn load_config<T: DeserializeOwned>(prefix: &str) -> Result<T, Error> {
    Figment::new()
        .merge(Env::prefixed(prefix))
        .extract()
        .map_err(|e| Error::Config(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::result_large_err)] // figment::Jail closures return figment::Error by contract
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TestCfg {
        host: String,
        port: u16,
    }

    #[test]
    fn loads_prefixed_env_vars() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("SWTEST_HOST", "localhost");
            jail.set_env("SWTEST_PORT", "5432");
            let cfg: TestCfg = load_config("SWTEST_").map_err(|e| e.to_string())?;
            assert_eq!(cfg.host, "localhost");
            assert_eq!(cfg.port, 5432);
            Ok(())
        });
    }

    #[test]
    fn missing_required_var_is_config_error() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("SWMISS_HOST", "localhost");
            let res: Result<TestCfg, Error> = load_config("SWMISS_");
            assert!(matches!(res, Err(Error::Config(_))));
            Ok(())
        });
    }
}
