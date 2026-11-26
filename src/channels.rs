//! Persistent, explicitly selected manifest channels for one application.
use crate::{Result, UpdateError, UpdateSource, client, local_state::PrivateDirectory};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

/// Name of the channel supplied by the running application.
pub const DEFAULT_CHANNEL: &str = "default";

/// One entry for a local channel settings interface. URLs can contain secrets.
#[derive(Clone, Serialize)]
pub struct ChannelInfo {
    /// Stable name used for selection.
    pub name: String,
    /// Configured manifest URL.
    pub manifest_url: String,
    /// Whether the application has selected this entry.
    pub selected: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    schema_version: u32,
    product_id: String,
    selected: String,
    channels: BTreeMap<String, String>,
}

/// Local registry of manifest channels. The default comes from the application on every open.
/// Mutations persist before returning and operate on the latest settings under a file lock.
#[derive(Clone)]
pub struct ChannelStore {
    directory: PrivateDirectory,
    default: UpdateSource,
}

fn valid_custom_name(name: &str) -> bool {
    name != DEFAULT_CHANNEL
        && !name.is_empty()
        && name == name.trim()
        && name.len() <= 128
        && !name.chars().any(char::is_control)
}

impl ChannelStore {
    /// Open a private application directory. A missing settings file selects the built-in
    /// source. Opening and managing channels never contacts a server.
    pub fn open(directory: &Path, default: UpdateSource) -> Result<Self> {
        if !client::valid_product_id(&default.product_id) {
            return Err(UpdateError::Unsupported("некорректный UUID приложения"));
        }
        Ok(Self {
            directory: PrivateDirectory::open(directory)?,
            default,
        })
    }

    fn read(&self) -> Result<Settings> {
        let Some(settings) = self.directory.read::<Settings>("channels.json")? else {
            return Ok(Settings {
                schema_version: 1,
                product_id: self.default.product_id.clone(),
                selected: DEFAULT_CHANNEL.into(),
                channels: BTreeMap::new(),
            });
        };
        if settings.product_id != self.default.product_id {
            return Err(UpdateError::Trust(
                "настройки каналов принадлежат другому приложению",
            ));
        }
        if settings.schema_version != 1
            || (settings.selected != DEFAULT_CHANNEL
                && !settings.channels.contains_key(&settings.selected))
        {
            return Err(UpdateError::Document);
        }
        for (name, url) in &settings.channels {
            if !valid_custom_name(name) {
                return Err(UpdateError::Document);
            }
            client::parse_url(url)?;
        }
        Ok(settings)
    }

    fn edit(&self, update: impl FnOnce(&mut Settings) -> Result<()>) -> Result<()> {
        let _lock = self.directory.lock("channels.lock")?;
        let mut settings = self.read()?;
        update(&mut settings)?;
        self.directory.write("channels.json", &settings)
    }

    /// List the built-in channel first, followed by custom channels in name order.
    pub fn list(&self) -> Result<Vec<ChannelInfo>> {
        let settings = self.read()?;
        let mut entries = vec![ChannelInfo {
            name: DEFAULT_CHANNEL.into(),
            manifest_url: self.default.manifest_url.clone(),
            selected: settings.selected == DEFAULT_CHANNEL,
        }];
        entries.extend(
            settings
                .channels
                .into_iter()
                .map(|(name, manifest_url)| ChannelInfo {
                    selected: name == settings.selected,
                    name,
                    manifest_url,
                }),
        );
        Ok(entries)
    }

    /// Save a new named channel without selecting it or replacing an existing entry.
    pub fn add(&self, name: &str, manifest_url: &str) -> Result<()> {
        if !valid_custom_name(name) {
            return Err(UpdateError::Unsupported(
                "недопустимое имя пользовательского канала",
            ));
        }
        client::parse_url(manifest_url)?;
        self.edit(|settings| {
            if settings.channels.contains_key(name) {
                return Err(UpdateError::Unsupported(
                    "канал с таким именем уже существует",
                ));
            }
            settings.channels.insert(name.into(), manifest_url.into());
            Ok(())
        })
    }

    /// Persist the selected channel, including [`DEFAULT_CHANNEL`] to return to the built-in source.
    pub fn select(&self, name: &str) -> Result<()> {
        self.edit(|settings| {
            if name != DEFAULT_CHANNEL && !settings.channels.contains_key(name) {
                return Err(UpdateError::Unsupported("неизвестный канал обновлений"));
            }
            settings.selected = name.into();
            Ok(())
        })
    }

    /// Remove an inactive custom channel. Select another channel before removing the active one.
    pub fn remove(&self, name: &str) -> Result<()> {
        self.edit(|settings| {
            if name == DEFAULT_CHANNEL || name == settings.selected {
                return Err(UpdateError::Unsupported(
                    "встроенный или выбранный канал нельзя удалить",
                ));
            }
            if settings.channels.remove(name).is_none() {
                return Err(UpdateError::Unsupported("неизвестный канал обновлений"));
            }
            Ok(())
        })
    }

    /// Resolve the current selection for a new client or monitor, retaining the application's
    /// key, product, origins and size limit. A custom channel reads signatures from its manifest.
    /// An existing client keeps its source for the lifetime of its operations.
    pub fn active_source(&self) -> Result<UpdateSource> {
        let mut settings = self.read()?;
        let mut source = self.default.clone();
        if let Some(url) = settings.channels.remove(&settings.selected) {
            source.manifest_url = url;
            source.descriptor_url.clear();
        }
        Ok(source)
    }
}
