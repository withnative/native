//! Atomic stored-image ingress and authenticated byte resolution for record bodies.
//!
//! This is an HTTP-neutral domain facade. The held host owns multipart and
//! response framing; attachment identity, policy, blobs, and body events stay
//! in the portable database transaction.

use std::io::Cursor;

use futures::future::BoxFuture;
use image::{AnimationDecoder, ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::authorization::{Capability, Principal};
use crate::blob::{self, BlobMeta, BlobSlice, BLOB_REF_FACET_KEY};
use crate::db::Db;
use crate::domain_transaction::{AttachmentCreate, AttachmentPhysicalPort};
use crate::mcp::Caller;
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, NormalizedRow,
    StatementTemplate,
};
use crate::store::AppendSpec;
use crate::{Error, Result};

pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_DIMENSION: u32 = 8_192;
pub const MAX_FRAME_PIXELS: u64 = 40_000_000;
pub const MAX_FRAMES: usize = 200;
pub const MAX_TOTAL_FRAME_PIXELS: u64 = 100_000_000;

const INSERT_VERSION: &str = "native.record-image-insert.v1";
const RESULT_VERSION: &str = "native.record-image-insert-result.v1";
const TOOL: &str = "insert_record_image";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageInsertMetadata {
    pub version: String,
    pub idempotency_key: String,
    pub if_body_digest: String,
    pub splice: ImageSplice,
    pub placement: ImagePlacement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSplice {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePlacement {
    pub alt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    pub size: ImageSize,
    pub alignment: ImageAlignment,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSize {
    Small,
    Medium,
    Wide,
    Full,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageAlignment {
    Left,
    Center,
    Right,
}

#[derive(Debug)]
pub enum RecordImageError {
    BadRequest(String),
    TooLarge(String),
    UnsupportedMedia(String),
    Conflict,
    NotFound,
    Internal(Error),
}

impl From<Error> for RecordImageError {
    fn from(error: Error) -> Self {
        Self::Internal(error)
    }
}

impl From<sqlx::Error> for RecordImageError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl From<serde_json::Error> for RecordImageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(error.into())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ImageInsertResult {
    pub version: &'static str,
    pub attachment_id: String,
    pub placement_source: String,
    pub body_digest: String,
    pub replayed: bool,
}

#[derive(Debug)]
pub struct ImageContent {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub filename: Option<String>,
    pub sha256: String,
}

struct ImageTransaction<'a> {
    db: &'a Db,
    tx: &'a mut Transaction<'static, Sqlite>,
}

impl DomainStatementExecutor for ImageTransaction<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, crate::portable_sql::SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            BorrowedSqliteStatementExecutor::new(self.tx)
                .fetch_all(statement, bindings, columns)
                .await
        })
    }
}

impl AttachmentPhysicalPort for ImageTransaction<'_> {
    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn insert_blob<'a>(
        &'a mut self,
        bytes: &'a [u8],
        mime: Option<&'a str>,
        filename: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlobMeta>> {
        Box::pin(async move { blob::insert_blob_in(self.tx, bytes, mime, filename).await })
    }

    fn read_blob_range<'a>(
        &'a mut self,
        blob_id: &'a str,
        offset: u64,
        length: u64,
    ) -> BoxFuture<'a, Result<Option<BlobSlice>>> {
        Box::pin(async move { blob::read_range_on(self.tx, blob_id, offset, length).await })
    }

    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            crate::store::append_in(self.db, self.tx, spec)
                .await
                .map(|_| ())
        })
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| {
        uuid.to_string() == value && uuid.get_version() == Some(uuid::Version::Random)
    })
}

fn validate_plain_text(
    value: &str,
    max: usize,
    field: &str,
) -> std::result::Result<(), RecordImageError> {
    let trimmed = value.trim();
    let count = trimmed.chars().count();
    if value != trimmed
        || count == 0
        || count > max
        || value.chars().any(|c| matches!(c, '\0' | '\r' | '\n'))
    {
        return Err(RecordImageError::BadRequest(format!(
            "{field} must be 1..={max} plain-text characters without NUL or line breaks"
        )));
    }
    Ok(())
}

fn escape_alt(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn escape_caption(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn placement_source(id: &str, placement: &ImagePlacement) -> String {
    let caption = placement
        .caption
        .as_deref()
        .map(|value| format!(" \"{}\"", escape_caption(value)))
        .unwrap_or_default();
    format!(
        "![{}](attachment:{id}{caption}){{size={} align={}}}",
        escape_alt(&placement.alt),
        serde_json::to_value(placement.size)
            .expect("enum serializes")
            .as_str()
            .unwrap(),
        serde_json::to_value(placement.alignment)
            .expect("enum serializes")
            .as_str()
            .unwrap(),
    )
}

pub fn validate_metadata(
    metadata: &ImageInsertMetadata,
    body: &str,
) -> std::result::Result<String, RecordImageError> {
    if metadata.version != INSERT_VERSION {
        return Err(RecordImageError::BadRequest(
            "unsupported image insert version".into(),
        ));
    }
    if !validate_uuid(&metadata.idempotency_key) {
        return Err(RecordImageError::BadRequest(
            "idempotency_key must be a canonical lowercase UUIDv4".into(),
        ));
    }
    if metadata.if_body_digest.len() != 64
        || !metadata
            .if_body_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(RecordImageError::BadRequest(
            "if_body_digest must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    if metadata.splice.start > metadata.splice.end
        || metadata.splice.end > body.len()
        || !body.is_char_boundary(metadata.splice.start)
        || !body.is_char_boundary(metadata.splice.end)
    {
        return Err(RecordImageError::BadRequest(
            "splice must be an ordered pair of UTF-8 byte boundaries within body".into(),
        ));
    }
    validate_plain_text(&metadata.placement.alt, 500, "placement.alt")?;
    if let Some(caption) = &metadata.placement.caption {
        validate_plain_text(caption, 1_000, "placement.caption")?;
    }
    Ok(placement_source(
        &metadata.idempotency_key,
        &metadata.placement,
    ))
}

fn exact_container_length(bytes: &[u8], format: ImageFormat) -> bool {
    match format {
        ImageFormat::Png => exact_png_length(bytes),
        ImageFormat::Jpeg => exact_jpeg_length(bytes),
        ImageFormat::Gif => exact_gif_length(bytes),
        ImageFormat::WebP if bytes.len() >= 12 => {
            bytes.get(0..4) == Some(b"RIFF")
                && bytes.get(8..12) == Some(b"WEBP")
                && u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize + 8 == bytes.len()
        }
        _ => false,
    }
}

fn exact_png_length(bytes: &[u8]) -> bool {
    if bytes.get(..8) != Some(b"\x89PNG\r\n\x1a\n") {
        return false;
    }
    let mut offset = 8_usize;
    loop {
        let Some(header) = bytes.get(offset..offset.saturating_add(8)) else {
            return false;
        };
        let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
        let end = match offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
        {
            Some(end) if end <= bytes.len() => end,
            _ => return false,
        };
        if &header[4..8] == b"IEND" {
            return length == 0 && end == bytes.len();
        }
        offset = end;
    }
}

fn exact_jpeg_length(bytes: &[u8]) -> bool {
    if bytes.get(..2) != Some(&[0xff, 0xd8]) {
        return false;
    }
    let mut offset = 2_usize;
    let mut entropy = false;
    while offset < bytes.len() {
        if bytes[offset] != 0xff {
            if entropy {
                offset += 1;
                continue;
            }
            return false;
        }
        while bytes.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let Some(&marker) = bytes.get(offset) else {
            return false;
        };
        offset += 1;
        if entropy && marker == 0x00 {
            continue;
        }
        if marker == 0xd9 {
            return offset == bytes.len();
        }
        if marker == 0xda {
            entropy = true;
        }
        if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
            continue;
        }
        let Some(length_bytes) = bytes.get(offset..offset.saturating_add(2)) else {
            return false;
        };
        let length = u16::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
        if length < 2 {
            return false;
        }
        offset = match offset.checked_add(length) {
            Some(end) if end <= bytes.len() => end,
            _ => return false,
        };
    }
    false
}

fn skip_gif_sub_blocks(bytes: &[u8], offset: &mut usize) -> bool {
    loop {
        let Some(&length) = bytes.get(*offset) else {
            return false;
        };
        *offset += 1;
        if length == 0 {
            return true;
        }
        *offset = match (*offset).checked_add(length as usize) {
            Some(end) if end <= bytes.len() => end,
            _ => return false,
        };
    }
}

fn exact_gif_length(bytes: &[u8]) -> bool {
    if !matches!(bytes.get(..6), Some(b"GIF87a") | Some(b"GIF89a")) || bytes.len() < 13 {
        return false;
    }
    let mut offset = 13_usize;
    let packed = bytes[10];
    if packed & 0x80 != 0 {
        offset = match offset.checked_add(3 * (1_usize << ((packed & 0x07) + 1))) {
            Some(end) if end <= bytes.len() => end,
            _ => return false,
        };
    }
    loop {
        match bytes.get(offset).copied() {
            Some(0x3b) => return offset + 1 == bytes.len(),
            Some(0x21) => {
                if bytes.get(offset + 1).is_none() {
                    return false;
                }
                offset += 2;
                if !skip_gif_sub_blocks(bytes, &mut offset) {
                    return false;
                }
            }
            Some(0x2c) => {
                let Some(descriptor) = bytes.get(offset + 1..offset + 10) else {
                    return false;
                };
                offset += 10;
                let packed = descriptor[8];
                if packed & 0x80 != 0 {
                    offset = match offset.checked_add(3 * (1_usize << ((packed & 0x07) + 1))) {
                        Some(end) if end <= bytes.len() => end,
                        _ => return false,
                    };
                }
                if bytes.get(offset).is_none() {
                    return false;
                }
                offset += 1;
                if !skip_gif_sub_blocks(bytes, &mut offset) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn check_dimensions(width: u32, height: u32) -> std::result::Result<u64, RecordImageError> {
    let pixels = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || pixels > MAX_FRAME_PIXELS
    {
        return Err(RecordImageError::TooLarge(
            "image dimensions exceed the v1 resource limits".into(),
        ));
    }
    Ok(pixels)
}

pub fn validate_image(bytes: &[u8]) -> std::result::Result<&'static str, RecordImageError> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(RecordImageError::TooLarge(
            "image exceeds the 10 MiB limit".into(),
        ));
    }
    let format = image::guess_format(bytes).map_err(|_| {
        RecordImageError::UnsupportedMedia("file is not a supported raster image".into())
    })?;
    let mime = match format {
        ImageFormat::Png => "image/png",
        ImageFormat::Jpeg => "image/jpeg",
        ImageFormat::WebP => "image/webp",
        ImageFormat::Gif => "image/gif",
        _ => {
            return Err(RecordImageError::UnsupportedMedia(
                "image format is not supported".into(),
            ))
        }
    };
    if !exact_container_length(bytes, format) {
        return Err(RecordImageError::UnsupportedMedia(
            "image container is malformed or has trailing data".into(),
        ));
    }
    let reader = ImageReader::with_format(Cursor::new(bytes), format);
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| RecordImageError::UnsupportedMedia("image cannot be decoded".into()))?;
    check_dimensions(width, height)?;

    let inspect_frames = |frames: &mut dyn Iterator<Item = image::ImageResult<image::Frame>>| {
        let mut total = 0_u64;
        for (index, frame) in frames.enumerate() {
            if index >= MAX_FRAMES {
                return Err(RecordImageError::TooLarge(
                    "image has more than 200 frames".into(),
                ));
            }
            let frame = frame.map_err(|_| {
                RecordImageError::UnsupportedMedia("image frames cannot be decoded".into())
            })?;
            let (width, height) = frame.buffer().dimensions();
            total = total.saturating_add(check_dimensions(width, height)?);
            if total > MAX_TOTAL_FRAME_PIXELS {
                return Err(RecordImageError::TooLarge(
                    "decoded image exceeds 100 megapixels".into(),
                ));
            }
        }
        Ok(())
    };
    match format {
        ImageFormat::Gif => {
            let decoder = image::codecs::gif::GifDecoder::new(Cursor::new(bytes))
                .map_err(|_| RecordImageError::UnsupportedMedia("GIF cannot be decoded".into()))?;
            inspect_frames(&mut decoder.into_frames())?;
        }
        ImageFormat::WebP => {
            let decoder = image::codecs::webp::WebPDecoder::new(Cursor::new(bytes))
                .map_err(|_| RecordImageError::UnsupportedMedia("WebP cannot be decoded".into()))?;
            inspect_frames(&mut decoder.into_frames())?;
        }
        _ => {
            ImageReader::with_format(Cursor::new(bytes), format)
                .decode()
                .map_err(|_| {
                    RecordImageError::UnsupportedMedia("image cannot be decoded".into())
                })?;
        }
    }
    Ok(mime)
}

fn request_digest(metadata: &ImageInsertMetadata, body: &str, bytes: &[u8]) -> Result<String> {
    let metadata_sha256 = sha256_hex(&serde_jcs::to_vec(metadata)?);
    let value = json!({
        "metadata_sha256": metadata_sha256,
        "body_sha256": sha256_hex(body.as_bytes()),
        "blob_sha256": sha256_hex(bytes),
    });
    Ok(sha256_hex(&serde_jcs::to_vec(&value)?))
}

fn replay_from_receipt(receipt: &Value, expected: &str) -> Option<ImageInsertResult> {
    if receipt.get("version")?.as_str()? != INSERT_VERSION
        || receipt.get("request_digest")?.as_str()? != expected
    {
        return None;
    }
    Some(ImageInsertResult {
        version: RESULT_VERSION,
        attachment_id: receipt.get("attachment_id")?.as_str()?.to_owned(),
        placement_source: receipt.get("placement_source")?.as_str()?.to_owned(),
        body_digest: receipt.get("body_digest")?.as_str()?.to_owned(),
        replayed: true,
    })
}

pub async fn insert_record_image(
    db: &Db,
    caller: &Caller,
    bearer_id: &str,
    metadata: ImageInsertMetadata,
    body: String,
    bytes: Vec<u8>,
    mime: &'static str,
) -> std::result::Result<ImageInsertResult, RecordImageError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(RecordImageError::TooLarge(
            "body exceeds the 4 MiB route limit".into(),
        ));
    }
    let derived_mime = validate_image(&bytes)?;
    if derived_mime != mime {
        return Err(RecordImageError::UnsupportedMedia(
            "declared image type does not match decoded bytes".into(),
        ));
    }
    let source = validate_metadata(&metadata, &body)?;
    let digest = request_digest(&metadata, &body, &bytes)?;
    let committed_body = format!(
        "{}{}{}",
        &body[..metadata.splice.start],
        source,
        &body[metadata.splice.end..]
    );
    let committed_digest = sha256_hex(committed_body.as_bytes());
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    {
        let mut port = ImageTransaction { db, tx: &mut tx };
        let principal = if caller.is_trusted_local() {
            Principal::trusted_local()
        } else {
            Principal::bound(caller.credential(), true)
        };
        if !crate::authorization::allows_record_with(
            &mut port,
            principal,
            bearer_id,
            Capability::Edit,
        )
        .await?
        {
            return Err(RecordImageError::NotFound);
        }

        if let Some(existing) = sqlx::query(
        "SELECT
           (SELECT payload FROM content_events WHERE record_id=records.id AND type='record.created' ORDER BY seq LIMIT 1) AS payload,
           (SELECT COUNT(*) FROM links WHERE source_id=records.id AND relationship='part_of') AS bearer_count,
           (SELECT target_id FROM links WHERE source_id=records.id AND relationship='part_of' ORDER BY id LIMIT 1) AS bearer_id
         FROM records WHERE id=?",
    )
    .bind(&metadata.idempotency_key)
    .fetch_optional(&mut **port.tx)
    .await?
    {
        if existing.try_get::<i64, _>("bearer_count")? != 1
            || existing.try_get::<Option<String>, _>("bearer_id")?.as_deref()
                != Some(bearer_id)
        {
            return Err(RecordImageError::Conflict);
        }
        let Some(payload) = existing.try_get::<Option<String>, _>("payload")? else {
            return Err(RecordImageError::Conflict);
        };
        let created: Value = serde_json::from_str(&payload)?;
        return replay_from_receipt(created.get("image_insert").unwrap_or(&Value::Null), &digest)
            .ok_or(RecordImageError::Conflict);
    }

        let row = sqlx::query("SELECT body, deleted_at FROM records WHERE id=?")
            .bind(bearer_id)
            .fetch_optional(&mut **port.tx)
            .await?;
        let Some(row) = row else {
            return Err(RecordImageError::NotFound);
        };
        if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
            return Err(RecordImageError::NotFound);
        }
        let stored_body: Option<String> = row.try_get("body")?;
        if sha256_hex(stored_body.as_deref().unwrap_or("").as_bytes()) != metadata.if_body_digest {
            return Err(RecordImageError::Conflict);
        }

        let receipt = json!({
            "version": INSERT_VERSION,
            "attachment_id": metadata.idempotency_key,
            "request_digest": digest,
            "metadata_sha256": sha256_hex(&serde_jcs::to_vec(&metadata)?),
            "body_sha256": sha256_hex(body.as_bytes()),
            "blob_sha256": sha256_hex(&bytes),
            "placement_source": source,
            "body_digest": committed_digest,
        });
        crate::domain_transaction::create_attachment(
            &mut port,
            AttachmentCreate {
                tool: TOOL,
                bearer_id,
                bytes: &bytes,
                mime: Some(mime),
                filename: metadata.filename.as_deref(),
                name: metadata.filename.as_deref().unwrap_or("image"),
                lifecycle: None,
                owner_id: None,
                persistence: Some("enduring"),
                maturity: None,
                extra_facets: Vec::new(),
                actor: caller.actor(),
                credential: caller.credential(),
                principal,
                attachment_id: Some(&metadata.idempotency_key),
                image_insert: Some(receipt),
            },
        )
        .await
        .map_err(|error| {
            if error.to_string().contains("does not exist") {
                RecordImageError::NotFound
            } else {
                RecordImageError::Internal(error)
            }
        })?;
        port.append_content(AppendSpec {
            record_id: bearer_id.to_owned(),
            event_type: "record.updated".into(),
            payload: json!({"body": committed_body}),
            actor: Some(caller.actor().into()),
        })
        .await?;
    }
    db.commit_content_for_domain(tx)
        .await
        .map_err(|error| RecordImageError::Internal(Error::engine(error.to_string())))?;
    Ok(ImageInsertResult {
        version: RESULT_VERSION,
        attachment_id: metadata.idempotency_key,
        placement_source: source,
        body_digest: committed_digest,
        replayed: false,
    })
}

pub async fn read_record_image(
    db: &Db,
    caller: &Caller,
    bearer_id: &str,
    attachment_id: &str,
) -> std::result::Result<ImageContent, RecordImageError> {
    let mut tx = db.write_pool().begin().await?;
    let mut port = ImageTransaction { db, tx: &mut tx };
    let principal = if caller.is_trusted_local() {
        Principal::trusted_local()
    } else {
        Principal::bound(caller.credential(), true)
    };
    if !crate::authorization::allows_record_with(&mut port, principal, bearer_id, Capability::View)
        .await?
    {
        return Err(RecordImageError::NotFound);
    }
    let row = sqlx::query(
        "SELECT r.type,r.kind,r.deleted_at,f.value AS blob_id,b.mime,b.size_bytes,b.sha256,b.original_filename,b.storage_tier,
         (SELECT payload FROM content_events e WHERE e.record_id=r.id AND e.type='record.created' ORDER BY e.seq LIMIT 1) AS created_payload,
         (SELECT COUNT(*) FROM links l WHERE l.source_id=r.id AND l.relationship='part_of') AS bearer_count,
         (SELECT target_id FROM links l WHERE l.source_id=r.id AND l.relationship='part_of' ORDER BY id LIMIT 1) AS bearer_id
         FROM records r LEFT JOIN facet_values f ON f.record_id=r.id AND f.key=?
         LEFT JOIN blobs b ON b.id=f.value WHERE r.id=?",
    )
    .bind(BLOB_REF_FACET_KEY)
    .bind(attachment_id)
    .fetch_optional(&mut **port.tx)
    .await?;
    let Some(row) = row else {
        return Err(RecordImageError::NotFound);
    };
    let is_image_insert = row
        .try_get::<Option<String>, _>("created_payload")?
        .and_then(|payload| serde_json::from_str::<Value>(&payload).ok())
        .and_then(|payload| {
            payload
                .pointer("/image_insert/version")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some(INSERT_VERSION);
    let visible_shape = row.try_get::<String, _>("type")? == "Document"
        && row.try_get::<Option<String>, _>("kind")?.as_deref() == Some("attachment")
        && row.try_get::<Option<String>, _>("deleted_at")?.is_none()
        && row.try_get::<i64, _>("bearer_count")? == 1
        && row.try_get::<Option<String>, _>("bearer_id")?.as_deref() == Some(bearer_id)
        && row.try_get::<Option<String>, _>("storage_tier")?.as_deref() == Some("inline")
        && is_image_insert
        && crate::authorization::allows_record_with(
            &mut port,
            principal,
            attachment_id,
            Capability::View,
        )
        .await?;
    if !visible_shape {
        return Err(RecordImageError::NotFound);
    }
    let mime = row
        .try_get::<Option<String>, _>("mime")?
        .ok_or(RecordImageError::NotFound)?;
    if !matches!(
        mime.as_str(),
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    ) {
        return Err(RecordImageError::NotFound);
    }
    let size = row.try_get::<i64, _>("size_bytes")?;
    if !(0..=MAX_IMAGE_BYTES as i64).contains(&size) {
        return Err(RecordImageError::NotFound);
    }
    let blob_id = row
        .try_get::<Option<String>, _>("blob_id")?
        .ok_or(RecordImageError::NotFound)?;
    let filename = row.try_get::<Option<String>, _>("original_filename")?;
    let sha256 = row
        .try_get::<Option<String>, _>("sha256")?
        .ok_or(RecordImageError::NotFound)?;
    let slice = blob::read_range_on(port.tx, &blob_id, 0, size as u64)
        .await?
        .ok_or(RecordImageError::NotFound)?;
    Ok(ImageContent {
        bytes: slice.bytes,
        mime,
        filename,
        sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png() -> Vec<u8> {
        let mut bytes = Vec::new();
        image::DynamicImage::new_rgba8(1, 1)
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();
        bytes
    }

    fn metadata(key: &str, body: &str) -> ImageInsertMetadata {
        ImageInsertMetadata {
            version: INSERT_VERSION.into(),
            idempotency_key: key.into(),
            if_body_digest: sha256_hex(body.as_bytes()),
            splice: ImageSplice {
                start: body.len(),
                end: body.len(),
            },
            placement: ImagePlacement {
                alt: "diagram".into(),
                caption: None,
                size: ImageSize::Medium,
                alignment: ImageAlignment::Center,
            },
            filename: Some("diagram.png".into()),
        }
    }

    #[test]
    fn placement_is_canonical_and_escaped() {
        let placement = ImagePlacement {
            alt: "A [map] \\ draft".into(),
            caption: Some("The \"map\"".into()),
            size: ImageSize::Wide,
            alignment: ImageAlignment::Center,
        };
        assert_eq!(
            placement_source("4f9787ae-f28f-4cd2-94d8-bbb6235eef50", &placement),
            "![A \\[map\\] \\\\ draft](attachment:4f9787ae-f28f-4cd2-94d8-bbb6235eef50 \"The \\\"map\\\"\"){size=wide align=center}"
        );
    }

    #[test]
    fn rejects_trailing_polyglot_bytes() {
        let mut bytes = png();
        bytes.extend_from_slice(b"<script>");
        assert!(matches!(
            validate_image(&bytes),
            Err(RecordImageError::UnsupportedMedia(_))
        ));
    }

    #[test]
    fn rejects_junk_followed_by_copied_terminal_marker() {
        for (format, terminal_len) in [
            (ImageFormat::Png, 12_usize),
            (ImageFormat::Jpeg, 2_usize),
            (ImageFormat::Gif, 1_usize),
        ] {
            let mut valid = Vec::new();
            let image = if format == ImageFormat::Jpeg {
                image::DynamicImage::new_rgb8(1, 1)
            } else {
                image::DynamicImage::new_rgba8(1, 1)
            };
            image
                .write_to(&mut Cursor::new(&mut valid), format)
                .unwrap();
            assert!(
                validate_image(&valid).is_ok(),
                "generated {format:?} must be valid"
            );
            let terminal = valid[valid.len() - terminal_len..].to_vec();
            valid.extend_from_slice(b"hostile trailing bytes");
            valid.extend_from_slice(&terminal);
            assert!(
                matches!(
                    validate_image(&valid),
                    Err(RecordImageError::UnsupportedMedia(_))
                ),
                "{format:?} must stop at its first real terminator"
            );
        }
    }

    #[tokio::test]
    async fn insert_replay_conflict_and_delivery_share_the_attachment_transaction() {
        let db = crate::create_database(":memory:").await.unwrap();
        crate::meta::seed_vocabularies(&db).await.unwrap();
        let body = "before\n";
        let bearer_id = crate::store::create_record(
            &db,
            json!({"type":"Collection","kind":"folder","name":"Bearer","body":body}),
        )
        .await
        .unwrap();
        let caller = Caller::local();
        let key = "4f9787ae-f28f-4cd2-94d8-bbb6235eef50";
        let bytes = png();
        let first = insert_record_image(
            &db,
            &caller,
            &bearer_id,
            metadata(key, body),
            body.into(),
            bytes.clone(),
            "image/png",
        )
        .await
        .unwrap();
        assert!(!first.replayed);
        let stored: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&bearer_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(stored, format!("{body}{}", first.placement_source));
        let content = read_record_image(&db, &caller, &bearer_id, key)
            .await
            .unwrap();
        assert_eq!(content.bytes, bytes);
        assert_eq!(content.mime, "image/png");
        let other_bearer = crate::store::create_record(
            &db,
            json!({"type":"Collection","kind":"folder","name":"Other"}),
        )
        .await
        .unwrap();
        assert!(matches!(
            read_record_image(&db, &caller, &other_bearer, key).await,
            Err(RecordImageError::NotFound)
        ));

        let replay = insert_record_image(
            &db,
            &caller,
            &bearer_id,
            metadata(key, body),
            body.into(),
            png(),
            "image/png",
        )
        .await
        .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.body_digest, first.body_digest);

        let mut changed = metadata(key, body);
        changed.placement.alt = "different".into();
        assert!(matches!(
            insert_record_image(
                &db,
                &caller,
                &bearer_id,
                changed,
                body.into(),
                png(),
                "image/png"
            )
            .await,
            Err(RecordImageError::Conflict)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM blobs")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn stale_digest_rolls_back_without_blob_or_attachment() {
        let db = crate::create_database(":memory:").await.unwrap();
        crate::meta::seed_vocabularies(&db).await.unwrap();
        let bearer_id = crate::store::create_record(
            &db,
            json!({"type":"Collection","kind":"folder","name":"Bearer","body":"current"}),
        )
        .await
        .unwrap();
        let body = "stale";
        let result = insert_record_image(
            &db,
            &Caller::local(),
            &bearer_id,
            metadata("9f9787ae-f28f-4cd2-94d8-bbb6235eef50", body),
            body.into(),
            png(),
            "image/png",
        )
        .await;
        assert!(matches!(result, Err(RecordImageError::Conflict)));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM blobs")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records WHERE id=?")
                .bind("9f9787ae-f28f-4cd2-94d8-bbb6235eef50")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
    }
}
