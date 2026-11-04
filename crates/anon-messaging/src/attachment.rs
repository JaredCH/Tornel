use crate::error::{MessageError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use image::{codecs::jpeg::JpegEncoder, DynamicImage, ImageDecoder, ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, io::Cursor};

pub const ATTACHMENT_PREFIX: &str = "ANON_ATTACHMENT_V1:";
const MAX_FILE_BYTES: usize = 360 * 1024;
const MAX_BODY_BYTES: usize = 520_000;

#[derive(Deserialize)]
struct IncomingAttachment {
    #[serde(rename = "dataUrl")]
    data_url: String,
    #[serde(default)]
    caption: String,
}

#[derive(Serialize)]
struct CleanAttachment {
    name: &'static str,
    mime: &'static str,
    size: usize,
    #[serde(rename = "dataUrl")]
    data_url: String,
    caption: String,
}

fn rejected(reason: &'static str) -> MessageError {
    MessageError::UnsafeAttachment(reason)
}

pub fn sanitize_body(body: &[u8]) -> Result<Cow<'_, [u8]>> {
    let Some(payload) = body.strip_prefix(ATTACHMENT_PREFIX.as_bytes()) else {
        return Ok(Cow::Borrowed(body));
    };
    if body.len() > MAX_BODY_BYTES {
        return Err(rejected("attachment envelope is too large"));
    }
    let incoming: IncomingAttachment =
        serde_json::from_slice(payload).map_err(|_| rejected("invalid attachment envelope"))?;
    let (header, encoded) = incoming
        .data_url
        .split_once(',')
        .ok_or_else(|| rejected("invalid attachment data URL"))?;
    if !header.starts_with("data:") || !header.ends_with(";base64") {
        return Err(rejected("attachment must contain base64 data"));
    }
    if encoded.len() > MAX_FILE_BYTES.div_ceil(3) * 4 {
        return Err(rejected("attachment exceeds 360 KB"));
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| rejected("invalid attachment base64"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(rejected("attachment exceeds 360 KB"));
    }
    let format = image::guess_format(&bytes).map_err(|_| {
        rejected("only JPEG and PNG images can be safely sanitized; other files are blocked")
    })?;
    if !matches!(format, ImageFormat::Jpeg | ImageFormat::Png) {
        return Err(rejected(
            "only JPEG and PNG images can be safely sanitized; other files are blocked",
        ));
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| rejected("image cannot be decoded within safety limits"))?;
    let (width, height) = decoder.dimensions();
    if width < 16 || height < 16 || u64::from(width) * u64::from(height) > 8_000_000 {
        return Err(rejected(
            "image must be at least 16x16 and at most 8 megapixels / 4096 per side",
        ));
    }
    let orientation = decoder
        .orientation()
        .map_err(|_| rejected("invalid image orientation"))?;
    let mut decoded = DynamicImage::from_decoder(decoder)
        .map_err(|_| rejected("image cannot be decoded within safety limits"))?;
    decoded.apply_orientation(orientation);
    let mut pixels = decoded.to_rgba8();
    for pixel in pixels.pixels_mut() {
        let alpha = u32::from(pixel[3]);
        for channel in &mut pixel.0[..3] {
            *channel = ((u32::from(*channel) * alpha + 255 * (255 - alpha)) / 255) as u8;
        }
        pixel[3] = 255;
    }
    let mut entropy = [0u8; 6];
    getrandom::fill(&mut entropy)
        .map_err(|_| rejected("secure image processing randomness unavailable"))?;
    let width = pixels.width();
    let height = pixels.height();
    let margins = [width, width, height, height]
        .into_iter()
        .zip(entropy)
        .map(|(dimension, random)| (dimension * (10 + u32::from(random % 11)) / 1000).max(1))
        .collect::<Vec<_>>();
    let cropped = DynamicImage::ImageRgba8(pixels).crop_imm(
        margins[0],
        margins[2],
        width - margins[0] - margins[1],
        height - margins[2] - margins[3],
    );
    let mut clean = cropped
        .resize(
            cropped.width().min(1280),
            cropped.height().min(1280),
            image::imageops::FilterType::Triangle,
        )
        .blur(0.6 + f32::from(entropy[4]) / 1024.0)
        .adjust_contrast(if entropy[5] & 1 == 0 { -0.5 } else { 0.5 })
        .brighten(if entropy[5] & 2 == 0 { -1 } else { 1 })
        .to_rgb8();
    let jpeg = loop {
        let mut output = Vec::new();
        JpegEncoder::new_with_quality(&mut output, 82)
            .encode_image(&clean)
            .map_err(|_| rejected("image encoding failed"))?;
        if output.len() <= MAX_FILE_BYTES {
            break output;
        }
        let width = clean.width() * 3 / 4;
        let height = clean.height() * 3 / 4;
        if width < 8 || height < 8 {
            return Err(rejected("sanitized image exceeds the transfer limit"));
        }
        clean =
            image::imageops::resize(&clean, width, height, image::imageops::FilterType::Triangle);
    };
    let clean = CleanAttachment {
        name: "image.jpg",
        mime: "image/jpeg",
        size: jpeg.len(),
        data_url: format!("data:image/jpeg;base64,{}", STANDARD.encode(jpeg)),
        caption: incoming.caption,
    };
    let mut output = ATTACHMENT_PREFIX.as_bytes().to_vec();
    serde_json::to_writer(&mut output, &clean)
        .map_err(|_| rejected("attachment encoding failed"))?;
    if output.len() > MAX_BODY_BYTES {
        return Err(rejected(
            "sanitized attachment and caption exceed the message limit",
        ));
    }
    Ok(Cow::Owned(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage};

    fn envelope(bytes: &[u8]) -> Vec<u8> {
        format!(
            "{ATTACHMENT_PREFIX}{}",
            serde_json::json!({
                "name": "Jane-GPS-camera-serial.jpg", "mime": "image/jpeg", "size": 1,
                "dataUrl": format!("data:image/jpeg;base64,{}", STANDARD.encode(bytes)),
                "caption": "hello", "exif": "private extra fields"
            })
        )
        .into_bytes()
    }

    #[test]
    fn strips_metadata_and_changes_image() {
        let original = RgbImage::from_pixel(100, 100, Rgb([100, 150, 200]));
        let mut jpeg = Vec::new();
        JpegEncoder::new_with_quality(&mut jpeg, 95)
            .encode_image(&original)
            .unwrap();
        let secret = b"Exif\0\0GPS-camera-serial-Jane";
        let length = (secret.len() as u16 + 2).to_be_bytes();
        jpeg.splice(
            2..2,
            [vec![0xff, 0xe1], length.to_vec(), secret.to_vec()].concat(),
        );
        jpeg.extend_from_slice(b"private trailing data");
        let body = envelope(&jpeg);
        let output = sanitize_body(&body).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&output[ATTACHMENT_PREFIX.len()..]).unwrap();
        assert_eq!(value["name"], "image.jpg");
        assert_eq!(value["mime"], "image/jpeg");
        assert_eq!(value["caption"], "hello");
        assert!(value.get("exif").is_none());
        let bytes = STANDARD
            .decode(
                value["dataUrl"]
                    .as_str()
                    .unwrap()
                    .split_once(',')
                    .unwrap()
                    .1,
            )
            .unwrap();
        assert_eq!(value["size"], bytes.len());
        for marker in [
            b"Exif".as_slice(),
            b"GPS",
            b"Jane",
            b"private",
            b"ICC_PROFILE",
            b"http://ns.adobe.com",
        ] {
            assert!(!bytes.windows(marker.len()).any(|part| part == marker));
        }
        let image = image::load_from_memory(&bytes).unwrap();
        assert!(image.width() < 100 && image.height() < 100);
        assert_ne!(image.to_rgb8().get_pixel(0, 0), original.get_pixel(0, 0));
    }

    #[test]
    fn rejects_unsupported_disguised_and_malformed_files() {
        for bytes in [
            b"%PDF-1.7 author=Jane".as_slice(),
            b"PK\x03\x04archive",
            b"<svg>private</svg>",
            b"\xff\xd8\xffbroken",
        ] {
            assert!(sanitize_body(&envelope(bytes)).is_err());
        }
        for payload in [
            "{}",
            "null",
            "not json",
            r#"{"dataUrl":"data:image/jpeg;base64,!!!"}"#,
        ] {
            assert!(sanitize_body(format!("{ATTACHMENT_PREFIX}{payload}").as_bytes()).is_err());
        }
        assert!(sanitize_body(&envelope(&vec![0; MAX_FILE_BYTES + 1])).is_err());
    }

    #[test]
    fn leaves_normal_messages_unchanged() {
        assert!(matches!(sanitize_body(b"hello").unwrap(), Cow::Borrowed(_)));
        assert_eq!(
            sanitize_body(b"\0binary MLS ciphertext").unwrap().as_ref(),
            b"\0binary MLS ciphertext"
        );
    }

    #[test]
    fn png_transparency_is_flattened_and_trailing_metadata_removed() {
        let original = image::RgbaImage::from_fn(40, 40, |column, row| {
            image::Rgba([column as u8, row as u8, 33, 0])
        });
        let mut png = Cursor::new(Vec::new());
        original.write_to(&mut png, ImageFormat::Png).unwrap();
        let mut bytes = png.into_inner();
        bytes.extend_from_slice(b"GPS Jane private");
        let body = envelope(&bytes);
        let output = sanitize_body(&body).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&output[ATTACHMENT_PREFIX.len()..]).unwrap();
        let bytes = STANDARD
            .decode(
                value["dataUrl"]
                    .as_str()
                    .unwrap()
                    .split_once(',')
                    .unwrap()
                    .1,
            )
            .unwrap();
        assert_eq!(image::guess_format(&bytes).unwrap(), ImageFormat::Jpeg);
        assert!(!bytes.windows(3).any(|part| part == b"GPS"));
        let clean = image::load_from_memory(&bytes).unwrap().to_rgb8();
        assert!(clean
            .pixels()
            .all(|pixel| pixel.0.iter().all(|channel| *channel >= 250)));
    }

    #[test]
    fn applies_exif_orientation_then_discards_all_source_segments() {
        let mut jpeg = Vec::new();
        JpegEncoder::new(&mut jpeg)
            .encode_image(&RgbImage::new(80, 40))
            .unwrap();
        let exif = b"Exif\0\0II\x2a\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0";
        for (marker, content) in [
            (0xe1, exif.as_slice()),
            (
                0xe1,
                b"http://ns.adobe.com/xap/1.0/\0private XMP".as_slice(),
            ),
            (0xe2, b"ICC_PROFILE\0\x01\x01private profile".as_slice()),
            (0xfe, b"private camera comment".as_slice()),
        ] {
            let length = (content.len() as u16 + 2).to_be_bytes();
            jpeg.splice(
                2..2,
                [vec![0xff, marker], length.to_vec(), content.to_vec()].concat(),
            );
        }
        let body = envelope(&jpeg);
        let output = sanitize_body(&body).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&output[ATTACHMENT_PREFIX.len()..]).unwrap();
        let bytes = STANDARD
            .decode(
                value["dataUrl"]
                    .as_str()
                    .unwrap()
                    .split_once(',')
                    .unwrap()
                    .1,
            )
            .unwrap();
        let clean = image::load_from_memory(&bytes).unwrap();
        assert!(clean.width() < 40 && clean.height() > 40 && clean.height() < 80);
        for marker in [0xe1, 0xe2, 0xfe] {
            assert!(!bytes.windows(2).any(|pair| pair == [0xff, marker]));
        }
    }

    #[test]
    fn rejects_unsafe_dimensions_and_oversized_captions() {
        for (width, height) in [(15, 40), (40, 15), (4097, 16), (3000, 3000)] {
            let mut png = Cursor::new(Vec::new());
            RgbImage::new(width, height)
                .write_to(&mut png, ImageFormat::Png)
                .unwrap();
            assert!(sanitize_body(&envelope(&png.into_inner())).is_err());
        }
        let mut png = Cursor::new(Vec::new());
        RgbImage::new(40, 40)
            .write_to(&mut png, ImageFormat::Png)
            .unwrap();
        let body = envelope(&png.into_inner());
        let mut payload: serde_json::Value =
            serde_json::from_slice(&body[ATTACHMENT_PREFIX.len()..]).unwrap();
        payload["caption"] = "x".repeat(MAX_BODY_BYTES - body.len()).into();
        let body = format!("{ATTACHMENT_PREFIX}{payload}");
        assert!(body.len() <= MAX_BODY_BYTES);
        assert!(sanitize_body(body.as_bytes()).is_err());
    }
}
