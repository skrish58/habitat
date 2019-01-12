// Copyright (c) 2016-2017 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;
use std::error;
use std::fmt;
use std::io;
use std::net;
use std::path::PathBuf;
use std::result;
use std::str;
use std::string;
use toml;

use crate::api_client;
use crate::hcore;
use crate::hcore::package::PackageIdent;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    APIClient(api_client::Error),
    ArtifactIdentMismatch((String, String, String)),
    CantUploadGossipToml,
    ChannelNotFound,
    CryptoKeyError(String),
    GossipFileRelativePath(String),
    DownloadFailed(String),
    EditStatus,
    /// Occurs when there is no valid toml of json in the environment variable
    BadEnvConfig(String),
    FileNameError,
    /// Occurs when a file that should exist does not or could not be read.
    FileNotFound(String),
    HabitatCore(hcore::Error),
    InstallHookFailed(PackageIdent),
    InvalidInstallHookMode(String),
    /// Occurs when making lower level IO calls.
    IO(io::Error),
    NetParseError(net::AddrParseError),
    /// Errors when joining paths :)
    JoinPathsError(env::JoinPathsError),
    OfflineArtifactNotFound(PackageIdent),
    OfflineOriginKeyNotFound(String),
    OfflinePackageNotFound(PackageIdent),
    /// Occurs upon errors related to file or directory permissions.
    PermissionFailed(String),
    /// When an error occurs serializing rendering context
    RenderContextSerialization(serde_json::Error),
    RootRequired,
    StrFromUtf8Error(str::Utf8Error),
    StringFromUtf8Error(string::FromUtf8Error),
    /// When an error occurs registering template file
    TemplateFileError(handlebars::TemplateFileError),
    /// When an error occurs rendering template
    /// The error is constructed with a handlebars::RenderError's format string instead
    /// of the handlebars::RenderError itself because the cause field of the
    /// handlebars::RenderError in the handlebars crate version we use implements send
    /// and not sync which can lead to upstream compile errors when dealing with the
    /// failure crate. We should change this to a RenderError after we update the
    /// handlebars crate. See https://github.com/sunng87/handlebars-rust/issues/194
    TemplateRenderError(String),
    /// When an error occurs merging toml
    TomlMergeError(String),
    /// When an error occurs parsing toml
    TomlParser(toml::de::Error),
    TomlSerializeError(toml::ser::Error),
    WireDecode(String),
    EditorEnv(env::VarError),
    PackageNotFound(String),
    StatusFileCorrupt(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match *self {
            Error::APIClient(ref err) => format!("{}", err),
            Error::ArtifactIdentMismatch((ref a, ref ai, ref i)) => format!(
                "Artifact ident {} for `{}' does not match expected ident {}",
                ai, a, i
            ),
            Error::BadEnvConfig(ref varname) => {
                format!("Unable to find valid TOML or JSON in {} ENVVAR", varname)
            }
            Error::CantUploadGossipToml => {
                format!("Can't upload gossip.toml, it's a reserved file name")
            }
            Error::ChannelNotFound => format!("Channel not found"),
            Error::CryptoKeyError(ref s) => format!("Missing or invalid key: {}", s),
            Error::GossipFileRelativePath(ref s) => format!(
                "Path for gossip file cannot have relative components (eg: ..): {}",
                s
            ),
            Error::DownloadFailed(ref msg) => format!("{}", msg),
            Error::EditStatus => format!("Failed edit text command"),
            Error::FileNameError => format!("Failed to extract a filename"),
            Error::FileNotFound(ref e) => format!("File not found at: {}", e),
            Error::HabitatCore(ref e) => format!("{}", e),
            Error::InstallHookFailed(ref ident) => {
                format!("Install hook exited unsuccessfully: {}", ident)
            }
            Error::InvalidInstallHookMode(ref e) => {
                format!("Invalid InstallHookMode conversion from {}", e)
            }
            Error::IO(ref err) => format!("{}", err),
            Error::NetParseError(ref err) => format!("{}", err),
            Error::JoinPathsError(ref err) => format!("{}", err),
            Error::OfflineArtifactNotFound(ref ident) => {
                format!("Cached artifact not found in offline mode: {}", ident)
            }
            Error::OfflineOriginKeyNotFound(ref name_with_rev) => format!(
                "Cached origin key not found in offline mode: {}",
                name_with_rev
            ),
            Error::OfflinePackageNotFound(ref ident) => format!(
                "No installed package or cached artifact could be found \
                 locally in offline mode: {}",
                ident
            ),
            Error::PermissionFailed(ref e) => format!("{}", e),
            Error::RenderContextSerialization(ref e) => {
                format!("Unable to serialize rendering context, {}", e)
            }
            Error::RootRequired => {
                "Root or administrator permissions required to complete operation".to_string()
            }
            Error::StrFromUtf8Error(ref e) => format!("{}", e),
            Error::StringFromUtf8Error(ref e) => format!("{}", e),
            Error::TemplateFileError(ref err) => format!("{:?}", err),
            Error::TemplateRenderError(ref e) => format!("{}", e),
            Error::TomlMergeError(ref e) => format!("Failed to merge TOML: {}", e),
            Error::TomlParser(ref err) => format!("Failed to parse TOML: {}", err),
            Error::TomlSerializeError(ref e) => format!("Can't serialize TOML: {}", e),
            Error::WireDecode(ref m) => format!("Failed to decode wire message: {}", m),
            Error::EditorEnv(ref e) => format!("Missing EDITOR environment variable: {}", e),
            Error::PackageNotFound(ref e) => format!("Package not found. {}", e),
            Error::StatusFileCorrupt(ref path) => format!(
                "Unable to decode contents of INSTALL_STATUS file, {}",
                path.display()
            ),
        };
        write!(f, "{}", msg)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::APIClient(ref err) => err.description(),
            Error::ArtifactIdentMismatch((_, _, _)) => {
                "Artifact ident does not match expected ident"
            }
            Error::BadEnvConfig(_) => "Unknown syntax in Env Configuration",
            Error::CantUploadGossipToml => "Can't upload gossip.toml, it's a reserved filename",
            Error::ChannelNotFound => "Channel not found",
            Error::CryptoKeyError(_) => "Missing or invalid key",
            Error::DownloadFailed(_) => "Failed to download from remote",
            Error::GossipFileRelativePath(_) => {
                "Path for gossip file cannot have relative components (eg: ..)"
            }
            Error::EditStatus => "Failed edit text command",
            Error::FileNameError => "Failed to extract a filename from a path",
            Error::FileNotFound(_) => "File not found",
            Error::HabitatCore(ref err) => err.description(),
            Error::InstallHookFailed(_) => "Install hook exited unsuccessfully",
            Error::InvalidInstallHookMode(_) => "Invalid InstallHookMode",
            Error::IO(ref err) => err.description(),
            Error::NetParseError(_) => "Can't parse IP:port",
            Error::JoinPathsError(ref err) => err.description(),
            Error::OfflineArtifactNotFound(_) => "Cached artifact not found in offline mode",
            Error::OfflineOriginKeyNotFound(_) => "Cached origin key not found in offline mode",
            Error::OfflinePackageNotFound(_) => {
                "No installed package or cached artifact could be found locally in offline mode"
            }
            Error::PermissionFailed(_) => "File system permissions error",
            Error::RenderContextSerialization(_) => "Unable to serialize rendering context",
            Error::RootRequired => {
                "Root or administrator permissions required to complete operation"
            }
            Error::StrFromUtf8Error(_) => "Failed to convert a string as UTF-8",
            Error::StringFromUtf8Error(_) => "Failed to convert a string as UTF-8",
            Error::TemplateFileError(ref err) => err.description(),
            Error::TemplateRenderError(_) => "Failed to render template",
            Error::TomlMergeError(_) => "Failed to merge TOML!",
            Error::TomlParser(_) => "Failed to parse TOML!",
            Error::TomlSerializeError(_) => "Can't serialize TOML",
            Error::WireDecode(_) => "Failed to decode wire message",
            Error::EditorEnv(_) => "Missing EDITOR environment variable",
            Error::PackageNotFound(_) => "Package not found",
            Error::StatusFileCorrupt(_) => "Unable to decode contents of INSTALL_STATUS file",
        }
    }
}

impl From<api_client::Error> for Error {
    fn from(err: api_client::Error) -> Self {
        Error::APIClient(err)
    }
}

impl From<handlebars::TemplateFileError> for Error {
    fn from(err: handlebars::TemplateFileError) -> Self {
        Error::TemplateFileError(err)
    }
}

impl From<hcore::Error> for Error {
    fn from(err: hcore::Error) -> Self {
        Error::HabitatCore(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<env::JoinPathsError> for Error {
    fn from(err: env::JoinPathsError) -> Self {
        Error::JoinPathsError(err)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Self {
        Error::StrFromUtf8Error(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Self {
        Error::StringFromUtf8Error(err)
    }
}

impl From<toml::ser::Error> for Error {
    fn from(err: toml::ser::Error) -> Self {
        Error::TomlSerializeError(err)
    }
}

impl From<net::AddrParseError> for Error {
    fn from(err: net::AddrParseError) -> Self {
        Error::NetParseError(err)
    }
}
