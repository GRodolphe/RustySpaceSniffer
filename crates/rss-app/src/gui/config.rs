//! Settings persistence (SPEC.md §3, §4.10): a single TOML file
//! `RustySpaceSniffer.toml` next to the exe, falling back to the per-user
//! config dir; unknown keys are preserved on save (FR-10.2); unwritable
//! locations degrade to non-persistent with a status notice (FR-10.3).
//!
//! Pure data + file I/O, no egui — unit-testable.

use std::path::{Path, PathBuf};

/// Three-way theme setting (FR-11.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ThemeSetting {
    /// Follow the OS application theme, live (default).
    #[default]
    System,
    Light,
    Dark,
}

impl ThemeSetting {
    pub fn label(self) -> &'static str {
        match self {
            ThemeSetting::System => "System",
            ThemeSetting::Light => "Light",
            ThemeSetting::Dark => "Dark",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

/// All persisted settings (FR-10.1). Unknown TOML keys are kept in `extra`
/// and written back verbatim on save (FR-10.2).
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub theme: ThemeSetting,
    pub flash_enabled: Option<bool>,
    pub zoom_anim_ms: Option<u64>,
    pub display_depth: Option<u32>,
    pub color_style: Option<String>,
    pub filter_history: Vec<String>,
    pub window_size: Option<(f32, f32)>,
    /// FR-7.6: live updates toggle (requires restart, FR-10.4).
    pub watch_enabled: Option<bool>,
    /// Keys we do not know (forward compatibility).
    pub extra: toml::Table,
}

impl Config {
    /// Parse a config file's contents; unknown keys land in `extra`.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        let mut table: toml::Table = toml::from_str(text)?;
        let mut config = Config::default();
        for (key, value) in std::mem::take(&mut table) {
            match key.as_str() {
                "theme" => {
                    if let Some(s) = value.as_str() {
                        config.theme = ThemeSetting::parse(s).unwrap_or_default();
                    }
                }
                "flash_enabled" => config.flash_enabled = value.as_bool(),
                "zoom_anim_ms" => {
                    config.zoom_anim_ms = value.as_integer().and_then(|v| u64::try_from(v).ok());
                }
                "display_depth" => {
                    config.display_depth = value.as_integer().and_then(|v| u32::try_from(v).ok());
                }
                "color_style" => {
                    config.color_style = value.as_str().map(str::to_string);
                }
                "filter_history" => {
                    if let Some(items) = value.as_array() {
                        config.filter_history = items
                            .iter()
                            .filter_map(|i| i.as_str().map(str::to_string))
                            .collect();
                    }
                }
                "window_size" => {
                    if let Some(pair) = value.as_array() {
                        if let (Some(w), Some(h)) = (
                            pair.first().and_then(|v| v.as_float()),
                            pair.get(1).and_then(|v| v.as_float()),
                        ) {
                            config.window_size = Some((w as f32, h as f32));
                        }
                    }
                }
                "watch_enabled" => config.watch_enabled = value.as_bool(),
                _ => {
                    config.extra.insert(key, value);
                }
            }
        }
        Ok(config)
    }

    /// Serialize; `extra` keys are written back first (FR-10.2).
    pub fn to_toml(&self) -> String {
        let mut table = self.extra.clone();
        table.insert(
            "theme".to_string(),
            toml::Value::String(self.theme.label().to_lowercase()),
        );
        if let Some(v) = self.flash_enabled {
            table.insert("flash_enabled".to_string(), toml::Value::Boolean(v));
        }
        if let Some(v) = self.zoom_anim_ms {
            table.insert("zoom_anim_ms".to_string(), toml::Value::Integer(v as i64));
        }
        if let Some(v) = self.display_depth {
            table.insert(
                "display_depth".to_string(),
                toml::Value::Integer(i64::from(v)),
            );
        }
        if let Some(v) = &self.color_style {
            table.insert("color_style".to_string(), toml::Value::String(v.clone()));
        }
        if !self.filter_history.is_empty() {
            table.insert(
                "filter_history".to_string(),
                toml::Value::Array(
                    self.filter_history
                        .iter()
                        .map(|f| toml::Value::String(f.clone()))
                        .collect(),
                ),
            );
        }
        if let Some((w, h)) = self.window_size {
            table.insert(
                "window_size".to_string(),
                toml::Value::Array(vec![
                    toml::Value::Float(f64::from(w)),
                    toml::Value::Float(f64::from(h)),
                ]),
            );
        }
        if let Some(v) = self.watch_enabled {
            table.insert("watch_enabled".to_string(), toml::Value::Boolean(v));
        }
        toml::to_string_pretty(&table).unwrap_or_default()
    }

    /// Load from a specific file; missing file yields defaults.
    pub fn load_from(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| Self::parse(&text).ok())
            .unwrap_or_default()
    }

    /// Save to a specific file, creating parent directories.
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_toml())
    }
}

/// The candidate config locations in priority order (SPEC.md §3): next to
/// the exe, then the per-user config directory.
pub fn config_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("RustySpaceSniffer.toml"));
        }
    }
    #[cfg(windows)]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        candidates.push(
            PathBuf::from(appdata)
                .join("RustySpaceSniffer")
                .join("config.toml"),
        );
    }
    #[cfg(not(windows))]
    {
        // Unix analog of the %APPDATA% fallback (development/testing).
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        if let Some(base) = base {
            candidates.push(base.join("rustyspacesniffer").join("config.toml"));
        }
    }
    candidates
}

/// Load the config from the first candidate that exists.
pub fn load() -> (Config, Option<PathBuf>) {
    for candidate in config_candidates() {
        if candidate.exists() {
            return (Config::load_from(&candidate), Some(candidate));
        }
    }
    (Config::default(), config_candidates().into_iter().next())
}

/// Save to `path` if given, else the first writable candidate. Returns the
/// path written, or `None` when no location is writable (FR-10.3).
pub fn save(config: &Config, path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = path {
        return config.save_to(path).ok().map(|_| path.to_path_buf());
    }
    config_candidates()
        .into_iter()
        .find(|candidate| config.save_to(candidate).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_known_and_unknown_keys() {
        let mut config = Config {
            theme: ThemeSetting::Dark,
            flash_enabled: Some(false),
            zoom_anim_ms: Some(250),
            display_depth: Some(3),
            color_style: Some("classes".to_string()),
            filter_history: vec!["*.jpg".to_string()],
            window_size: Some((1024.0, 768.0)),
            watch_enabled: Some(false),
            extra: toml::Table::new(),
        };
        config.extra.insert(
            "future_feature".to_string(),
            toml::Value::String("keepme".to_string()),
        );
        let text = config.to_toml();
        let parsed = Config::parse(&text).unwrap();
        assert_eq!(parsed.theme, ThemeSetting::Dark);
        assert_eq!(parsed.flash_enabled, Some(false));
        assert_eq!(parsed.zoom_anim_ms, Some(250));
        assert_eq!(parsed.display_depth, Some(3));
        assert_eq!(parsed.color_style.as_deref(), Some("classes"));
        assert_eq!(parsed.filter_history, vec!["*.jpg"]);
        assert_eq!(parsed.window_size, Some((1024.0, 768.0)));
        assert_eq!(parsed.watch_enabled, Some(false));
        // FR-10.2: unknown keys survive the round-trip.
        assert_eq!(
            parsed.extra.get("future_feature").and_then(|v| v.as_str()),
            Some("keepme")
        );
    }

    #[test]
    fn load_save_to_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let config = Config {
            theme: ThemeSetting::Light,
            ..Default::default()
        };
        config.save_to(&path).unwrap();
        assert_eq!(Config::load_from(&path).theme, ThemeSetting::Light);
    }
}
