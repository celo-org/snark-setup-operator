// Based on: https://github.com/microsoft/avml/blob/main/src/blobstore.rs

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

pub const ONE_MB: usize = 1024 * 1024;

use crate::error::{HttpError, UtilsError};
use anyhow::Result;
use azure_core::{BlobNameSupport, BlockIdSupport, BodySupport, ContainerNameSupport};
use azure_storage::blob::blob::{BlobBlockType, BlockList, BlockListSupport};
use azure_storage::blob::container::{PublicAccess, PublicAccessSupport};
use azure_storage::core::key_client::KeyClient;
use azure_storage::{client, Blob, Container};
use byteorder::{LittleEndian, WriteBytesExt};
use futures_retry::{FutureRetry, RetryPolicy};
use std::cmp;
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::ops::Deref;
use tracing::warn;
use url::Url;

const MAX_BLOCK_SIZE: usize = ONE_MB * 100;

/// Converts the block index into an block_id
fn to_id(count: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    bytes.write_u64::<LittleEndian>(count)?;
    Ok(bytes)
}

/// Parse a SAS token into the relevant components
fn parse_sas(sas: &str) -> Result<(String, String, String)> {
    let parsed = Url::parse(sas)?;
    let account = if let Some(host) = parsed.host_str() {
        let v: Vec<&str> = host.split_terminator('.').collect();
        v[0]
    } else {
        return Err(HttpError::CouldNotParseSAS(sas.to_string()).into());
    };

    let path = parsed.path();
    let mut v: Vec<&str> = path.split_terminator('/').collect();
    v.remove(0);
    let container = v.remove(0);
    let blob_path = v.join("/");
    Ok((account.to_string(), container.to_string(), blob_path))
}

pub async fn upload_sas(file_path: &str, sas: &str) -> Result<()> {
    let (account, container, path) = parse_sas(sas)?;
    let client = client::with_azure_sas(&account, sas);

    upload_with_client_with_retries(&client, &container, &path, file_path).await
}

pub async fn upload_access_key(
    file_path: &str,
    access_key: &str,
    account: &str,
    container: &str,
    path: &str,
) -> Result<()> {
    let client = client::with_access_key(account, access_key);
    let mut found_container = false;
    for remote_container in client
        .list_containers()
        .finalize()
        .await?
        .incomplete_vector
        .deref()
        .into_iter()
    {
        if container == remote_container.name {
            found_container = true;
            break;
        }
    }
    if !found_container {
        client
            .create_container()
            .with_container_name(container)
            .with_public_access(PublicAccess::Container)
            .finalize()
            .await?;
    }
    upload_with_client_with_retries(&client, container, path, file_path).await
}

fn handle_error(e: anyhow::Error) -> RetryPolicy<anyhow::Error> {
    warn!("Failed uploading: {0}, retrying...", e.to_string());
    RetryPolicy::WaitRetry(
        chrono::Duration::seconds(5)
            .to_std()
            .expect("Should have converted to standard duration"),
    )
}

pub async fn upload_with_client_with_retries(
    client: &KeyClient,
    container: &str,
    path: &str,
    file_path: &str,
) -> Result<()> {
    FutureRetry::new(
        move || upload_with_client(client, container, path, file_path),
        handle_error,
    )
    .await
    .map_err(|e| UtilsError::RetryFailedError(e.0.to_string()))?;
    Ok(())
}

pub async fn upload_with_client(
    client: &KeyClient,
    container: &str,
    path: &str,
    file_path: &str,
) -> Result<()> {
    let block_size = MAX_BLOCK_SIZE;

    let mut file = File::open(file_path)?;
    let size = usize::try_from(file.metadata()?.len())?;
    let mut sent = 0;
    let mut blocks = BlockList { blocks: Vec::new() };
    let mut futures = vec![];
    while sent < size {
        let send_size = cmp::min(block_size, size - sent);
        let block_id = to_id(sent as u64)?;
        let mut data = vec![0; send_size];
        file.read_exact(&mut data)?;

        let client = client.clone();
        let container = container.to_string();
        let path = path.to_string();
        let block_id_for_spawn = block_id.clone();
        let jh = tokio::spawn(async move {
            client
                .put_block()
                .with_container_name(&container)
                .with_blob_name(&path)
                .with_body(&data)
                .with_block_id(&block_id_for_spawn)
                .finalize()
                .await
        });
        futures.push(jh);

        blocks.blocks.push(BlobBlockType::Uncommitted(block_id));
        sent += send_size;
    }

    futures::future::try_join_all(futures).await?;

    client
        .put_block_list()
        .with_container_name(&container)
        .with_blob_name(&path)
        .with_block_list(&blocks)
        .finalize()
        .await?;

    Ok(())
}
