//! internet.rs — Internet Fetcher: acesso controlado à internet
//!
//! NexoIA consulta a internet apenas para:
//! - Documentação Rust (doc.rust-lang.org)
//! - Próprio repositório (github.com/JoseSmurf/nexoia)
//! - APIs de erros (crates.io, docs.rs)
//!
//! Tudo é cacheado localmente em data/knowledge/cache/
//! Cache usa BLAKE3 do URL como chave. TTL: 24h.
//! Modo offline-first: se cache existe, usa cache.

use crate::hash::canonical_hash;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Domínios permitidos para acesso
const ALLOWED_DOMAINS: &[&str] = &[
    "doc.rust-lang.org",
    "crates.io",
    "docs.rs",
    "raw.githubusercontent.com",
    "github.com",
];

/// TTL do cache em segundos (24h)
const CACHE_TTL_SECS: u64 = 86400;

/// Tamanho máximo de uma resposta em bytes (1MB)
#[allow(dead_code)]
const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// Timeout de requisição em segundos
#[allow(dead_code)]
const REQUEST_TIMEOUT_SECS: u64 = 5;

/// Entrada de cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub url: String,
    pub url_hash: String,
    pub content_hash: String,
    pub fetched_at: u64,
    pub content: String,
    pub content_type: String,
}

/// Resultado de uma busca
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FetchResult {
    pub content: String,
    pub from_cache: bool,
    pub url: String,
    pub content_hash: String,
}

/// Internet Fetcher — acesso controlado e cacheado
#[allow(dead_code)]
pub struct InternetFetcher {
    cache_dir: PathBuf,
    client: Option<reqwest::Client>,
}

impl InternetFetcher {
    /// Cria novo fetcher
    #[allow(dead_code)]
    pub fn new(data_dir: &Path) -> Self {
        let cache_dir = data_dir.join("knowledge").join("cache");
        fs::create_dir_all(&cache_dir).ok();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("nexoia/0.1.0 (evidence-engine)")
            .build()
            .ok();

        Self { cache_dir, client }
    }

    /// Versão para testes — sem cliente HTTP real
    #[allow(dead_code)]
    pub fn new_fake(data_dir: &Path) -> Self {
        let cache_dir = data_dir.join("knowledge").join("cache");
        fs::create_dir_all(&cache_dir).ok();

        Self {
            cache_dir,
            client: None,
        }
    }

    /// Busca conteúdo de uma URL (com cache)
    #[allow(dead_code)]
    pub async fn fetch(&self, url: &str) -> Result<FetchResult, String> {
        // 1. Valida domínio
        self.validate_url(url)?;

        // 2. Gera hash do URL para chave de cache
        let url_hash = canonical_hash(url);
        let cache_path = self.cache_dir.join(format!("{}.json", &url_hash[..16]));

        // 3. Verifica cache
        if let Ok(content) = fs::read_to_string(&cache_path) {
            if let Ok(entry) = serde_json::from_str::<CacheEntry>(&content) {
                if self.is_cache_fresh(&entry) {
                    return Ok(FetchResult {
                        content: entry.content,
                        from_cache: true,
                        url: url.to_string(),
                        content_hash: entry.content_hash,
                    });
                }
            }
        }

        // 4. Busca da internet
        let client = self
            .client
            .as_ref()
            .ok_or("InternetFetcher offline (sem cliente HTTP)")?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Erro ao buscar {}: {}", url, e))?;

        let status = response.status();
        if !status.is_success() {
            return Err(format!("HTTP {} ao buscar {}", status, url));
        }

        let content = response
            .text()
            .await
            .map_err(|e| format!("Erro ao ler resposta: {}", e))?;

        // 5. Valida tamanho
        if content.len() > MAX_RESPONSE_BYTES {
            return Err(format!(
                "Resposta muito grande: {} bytes (máx: {})",
                content.len(),
                MAX_RESPONSE_BYTES
            ));
        }

        // 6. Detecta content-type
        let content_type = self.detect_content_type(url, &content);

        // 7. Salva no cache
        let content_hash = canonical_hash(&content);
        let entry = CacheEntry {
            url: url.to_string(),
            url_hash: url_hash.clone(),
            content_hash: content_hash.clone(),
            fetched_at: Self::now(),
            content: content.clone(),
            content_type,
        };

        let _ = fs::write(
            &cache_path,
            serde_json::to_string(&entry).unwrap_or_default(),
        );

        Ok(FetchResult {
            content,
            from_cache: false,
            url: url.to_string(),
            content_hash,
        })
    }

    /// Busca offline — só retorna cache, não acessa internet
    #[allow(dead_code)]
    pub fn fetch_offline(&self, url: &str) -> Result<FetchResult, String> {
        self.validate_url(url)?;

        let url_hash = canonical_hash(url);
        let cache_path = self.cache_dir.join(format!("{}.json", &url_hash[..16]));

        if let Ok(content) = fs::read_to_string(&cache_path) {
            if let Ok(entry) = serde_json::from_str::<CacheEntry>(&content) {
                return Ok(FetchResult {
                    content: entry.content,
                    from_cache: true,
                    url: url.to_string(),
                    content_hash: entry.content_hash,
                });
            }
        }

        Err(format!("Cache não encontrado para {}", url))
    }

    /// Valida se a URL é de um domínio permitido
    fn validate_url(&self, url: &str) -> Result<(), String> {
        // Extrai domínio do URL
        let domain = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let domain = domain
            .split('/')
            .next()
            .unwrap_or(domain)
            .split(':')
            .next()
            .unwrap_or(domain);

        if ALLOWED_DOMAINS
            .iter()
            .any(|allowed| domain == *allowed || domain.ends_with(&format!(".{}", allowed)))
        {
            Ok(())
        } else {
            Err(format!(
                "Domínio não permitido: {}. Permitidos: {:?}",
                domain, ALLOWED_DOMAINS
            ))
        }
    }

    /// Verifica se o cache ainda é válido
    fn is_cache_fresh(&self, entry: &CacheEntry) -> bool {
        let now = Self::now();
        now.saturating_sub(entry.fetched_at) < CACHE_TTL_SECS
    }

    /// Detecta content-type baseado na URL e conteúdo
    #[allow(dead_code)]
    fn detect_content_type(&self, url: &str, content: &str) -> String {
        if url.ends_with(".json") || content.starts_with('{') || content.starts_with('[') {
            "application/json".to_string()
        } else if url.ends_with(".rs")
            || url.contains("doc.rust-lang.org")
            || url.contains("/rust/")
        {
            "text/rust".to_string()
        } else if url.ends_with(".md") || url.contains("github.com") {
            "text/markdown".to_string()
        } else if url.ends_with(".html") || url.contains("docs.rs") {
            "text/html".to_string()
        } else {
            "text/plain".to_string()
        }
    }

    /// Timestamp atual em segundos desde UNIX
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Limpa cache expirado
    #[allow(dead_code)]
    pub fn cleanup_cache(&self) -> usize {
        let mut removed = 0;
        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(cache_entry) = serde_json::from_str::<CacheEntry>(&content) {
                            if !self.is_cache_fresh(&cache_entry) {
                                let _ = fs::remove_file(&path);
                                removed += 1;
                            }
                        }
                    }
                }
            }
        }
        removed
    }

    /// Estatísticas do cache
    #[allow(dead_code)]
    pub fn cache_stats(&self) -> CacheStats {
        let mut total = 0;
        let mut fresh = 0;
        let mut stale = 0;

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    total += 1;
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(cache_entry) = serde_json::from_str::<CacheEntry>(&content) {
                            if self.is_cache_fresh(&cache_entry) {
                                fresh += 1;
                            } else {
                                stale += 1;
                            }
                        }
                    }
                }
            }
        }

        CacheStats {
            total,
            fresh,
            stale,
        }
    }
}

/// Estatísticas do cache
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CacheStats {
    pub total: usize,
    pub fresh: usize,
    pub stale: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn internet_validate_url_allowed() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new(dir.path());

        assert!(fetcher
            .validate_url("https://doc.rust-lang.org/std/")
            .is_ok());
        assert!(fetcher
            .validate_url("https://crates.io/api/v1/crates/blake3")
            .is_ok());
        assert!(fetcher
            .validate_url("https://docs.rs/reqwest/latest/")
            .is_ok());
        assert!(fetcher
            .validate_url("https://github.com/JoseSmurf/nexoia")
            .is_ok());
        assert!(fetcher
            .validate_url("https://raw.githubusercontent.com/JoseSmurf/nexoia/main/Cargo.toml")
            .is_ok());
    }

    #[test]
    fn internet_validate_url_blocked() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new(dir.path());

        assert!(fetcher.validate_url("https://evil.com/hack").is_err());
        assert!(fetcher.validate_url("https://malware.ru/virus").is_err());
        assert!(fetcher.validate_url("http://google.com").is_err());
        assert!(fetcher.validate_url("https://notallowed.org/x").is_err());
    }

    #[test]
    fn internet_fetch_offline_without_cache_fails() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new_fake(dir.path());

        let result = fetcher.fetch_offline("https://doc.rust-lang.org/std/");
        assert!(result.is_err());
    }

    #[test]
    fn internet_fetch_offline_with_cache_works() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new_fake(dir.path());

        // Cria entrada de cache manualmente
        let url = "https://doc.rust-lang.org/std/";
        let url_hash = canonical_hash(url);
        let cache_path = dir
            .path()
            .join("knowledge")
            .join("cache")
            .join(format!("{}.json", &url_hash[..16]));

        let entry = CacheEntry {
            url: url.to_string(),
            url_hash: url_hash.clone(),
            content_hash: canonical_hash("test content"),
            fetched_at: InternetFetcher::now(),
            content: "test content".to_string(),
            content_type: "text/rust".into(),
        };

        fs::create_dir_all(cache_path.parent().unwrap()).ok();
        fs::write(&cache_path, serde_json::to_string(&entry).unwrap()).ok();

        let result = fetcher.fetch_offline(url);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.content, "test content");
        assert!(result.from_cache);
    }

    #[test]
    fn internet_cache_freshness() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new(dir.path());

        let fresh_entry = CacheEntry {
            url: "test".into(),
            url_hash: "h".into(),
            content_hash: "c".into(),
            fetched_at: InternetFetcher::now(),
            content: String::new(),
            content_type: String::new(),
        };

        let stale_entry = CacheEntry {
            url: "test".into(),
            url_hash: "h".into(),
            content_hash: "c".into(),
            fetched_at: InternetFetcher::now() - CACHE_TTL_SECS - 1,
            content: String::new(),
            content_type: String::new(),
        };

        assert!(fetcher.is_cache_fresh(&fresh_entry));
        assert!(!fetcher.is_cache_fresh(&stale_entry));
    }

    #[test]
    fn internet_content_type_detection() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new(dir.path());

        assert_eq!(
            fetcher.detect_content_type("https://api.github.com/repos/x", "{}"),
            "application/json"
        );
        assert_eq!(
            fetcher.detect_content_type("https://doc.rust-lang.org/std/", "fn main()"),
            "text/rust"
        );
        assert_eq!(
            fetcher.detect_content_type("https://github.com/JoseSmurf/nexoia", "# Title"),
            "text/markdown"
        );
    }

    #[test]
    fn internet_cache_stats_empty() {
        let dir = tempdir().unwrap();
        let fetcher = InternetFetcher::new(dir.path());

        let stats = fetcher.cache_stats();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.fresh, 0);
        assert_eq!(stats.stale, 0);
    }
}
