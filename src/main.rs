use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use fastnbt::Value;
use flate2::{
    Compression as FlateCompression,
    read::{GzDecoder, ZlibDecoder},
    write::{GzEncoder, ZlibEncoder},
};
use walkdir::WalkDir;

const SECTOR_BYTES: usize = 4096;
const CHUNK_COUNT: usize = 1024;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Replace strings inside Minecraft NBT files (.dat, .nbt, region/*.mca)."
)]
struct Args {
    /// Path to the Minecraft world directory to scan
    path: PathBuf,
    /// String to replace
    old: String,
    /// Replacement string
    new: String,
    /// Scan without writing any changes
    #[arg(short, long)]
    dry_run: bool,
}

#[derive(Default)]
struct Stats {
    files_scanned: u64,
    files_modified: u64,
    replacements: u64,
    errors: Vec<(PathBuf, String)>,
}

fn progress(msg: impl AsRef<str>) {
    println!("{}", msg.as_ref());
    let _ = std::io::stdout().flush();
}

#[derive(Clone, Copy)]
enum NbtCompression {
    None,
    Gzip,
    Zlib,
}

#[derive(Clone)]
struct ChunkEntry {
    payload: Vec<u8>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.old.is_empty() {
        bail!("OLD string cannot be empty");
    }

    let stats = run(&args)?;

    println!(
        "Scanned {} files | replacements: {} | modified: {}{}",
        stats.files_scanned,
        stats.replacements,
        stats.files_modified,
        if args.dry_run { " (dry-run)" } else { "" }
    );

    if !stats.errors.is_empty() {
        eprintln!("Encountered {} errors:", stats.errors.len());
        for (path, err) in stats.errors {
            eprintln!(" - {}: {}", path.display(), err);
        }
    }

    Ok(())
}

fn run(args: &Args) -> Result<Stats> {
    let mut stats = Stats::default();

    let mut targets: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(&args.path).into_iter() {
        match entry {
            Ok(entry) => {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.into_path();
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                match ext.as_str() {
                    "nbt" | "dat" | "mca" => targets.push(path),
                    _ => {}
                }
            }
            Err(err) => {
                let path = err
                    .path()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| args.path.clone());
                stats
                    .errors
                    .push((path, format!("Failed to read entry: {err}")));
            }
        }
    }

    let total = targets.len();

    for (idx, path) in targets.into_iter().enumerate() {
        let display = path.display().to_string();
        let current = idx + 1;
        let percent = if total == 0 {
            100.0
        } else {
            (current as f64 / total as f64) * 100.0
        };

        let result = match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default()
            .as_str()
        {
            "nbt" | "dat" => {
                stats.files_scanned += 1;
                progress(format!(
                    "[{}/{} {:>5.1}%] Processing {} (nbt/dat)",
                    current, total, percent, display
                ));
                process_nbt_file(&path, args)
            }
            "mca" => {
                stats.files_scanned += 1;
                progress(format!(
                    "[{}/{} {:>5.1}%] Processing {} (region)",
                    current, total, percent, display
                ));
                process_region_file(&path, args)
            }
            _ => continue,
        };

        match result {
            Ok((replacements, modified)) => {
                stats.replacements += replacements;
                if modified {
                    stats.files_modified += 1;
                }
                progress(format!(
                    "[{}/{} {:>5.1}%] Processed {} -> replacements: {}, wrote: {}",
                    current, total, percent, display, replacements, modified
                ));
            }
            Err(err) => {
                progress(format!(
                    "[{}/{} {:>5.1}%] Failed {}: {}",
                    current, total, percent, display, err
                ));
                stats.errors.push((path, err.to_string()));
            }
        }
    }

    Ok(stats)
}

fn process_nbt_file(path: &Path, args: &Args) -> Result<(u64, bool)> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let (mut value, compression) = parse_nbt(&data)
        .with_context(|| format!("Failed to parse NBT data from {}", path.display()))?;

    let replacements = replace_in_value(&mut value, &args.old, &args.new);

    if replacements == 0 {
        return Ok((0, false));
    }

    if args.dry_run {
        return Ok((replacements, false));
    }

    let encoded = fastnbt::to_bytes(&value).context("Failed to encode NBT data")?;
    let final_bytes = match compression {
        NbtCompression::None => encoded,
        NbtCompression::Gzip => compress_gzip(&encoded)?,
        NbtCompression::Zlib => compress_zlib(&encoded)?,
    };

    std::fs::write(path, final_bytes)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    Ok((replacements, true))
}

fn parse_nbt(data: &[u8]) -> Result<(Value, NbtCompression)> {
    if let Ok(buf) = decompress_gzip(data) {
        if let Ok(value) = fastnbt::from_bytes(&buf) {
            return Ok((value, NbtCompression::Gzip));
        }
    }

    if let Ok(buf) = decompress_zlib(data) {
        if let Ok(value) = fastnbt::from_bytes(&buf) {
            return Ok((value, NbtCompression::Zlib));
        }
    }

    let value = fastnbt::from_bytes(data)?;
    Ok((value, NbtCompression::None))
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
}

fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), FlateCompression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn compress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), FlateCompression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn process_region_file(path: &Path, args: &Args) -> Result<(u64, bool)> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < SECTOR_BYTES * 2 {
        bail!("{} is too small to be a valid region file", path.display());
    }

    let mut timestamps = [0u32; CHUNK_COUNT];
    for i in 0..CHUNK_COUNT {
        let idx = SECTOR_BYTES + i * 4;
        timestamps[i] =
            u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
    }

    let mut chunks: Vec<Option<ChunkEntry>> = vec![None; CHUNK_COUNT];
    let mut total_replacements = 0u64;

    for i in 0..CHUNK_COUNT {
        let header_idx = i * 4;
        let offset = ((data[header_idx] as u32) << 16)
            | ((data[header_idx + 1] as u32) << 8)
            | (data[header_idx + 2] as u32);
        let sector_count = data[header_idx + 3] as u32;

        if offset == 0 || sector_count == 0 {
            continue;
        }

        let start = offset as usize * SECTOR_BYTES;
        let length = sector_count as usize * SECTOR_BYTES;
        if start + length > data.len() {
            bail!(
                "{} chunk {} extends beyond file bounds (start {}, len {}, file {})",
                path.display(),
                i,
                start,
                length,
                data.len()
            );
        }

        let chunk_slice = &data[start..start + length];
        if chunk_slice.len() < 5 {
            bail!(
                "{} chunk {} is too small ({} bytes)",
                path.display(),
                i,
                chunk_slice.len()
            );
        }

        let chunk_length = u32::from_be_bytes(chunk_slice[0..4].try_into().unwrap()) as usize;
        if chunk_length == 0 || chunk_length + 4 > chunk_slice.len() {
            bail!(
                "{} chunk {} has invalid length {} (buffer {})",
                path.display(),
                i,
                chunk_length,
                chunk_slice.len()
            );
        }

        let compression_type = chunk_slice[4];
        if chunk_length < 1 {
            bail!("{} chunk {} missing compression byte", path.display(), i);
        }

        let data_end = 5 + chunk_length - 1;
        if data_end > chunk_slice.len() {
            bail!(
                "{} chunk {} compressed section exceeds bounds ({} > {})",
                path.display(),
                i,
                data_end,
                chunk_slice.len()
            );
        }

        let compressed_data = &chunk_slice[5..data_end];
        let uncompressed = decompress_chunk(compression_type, compressed_data)
            .with_context(|| format!("Failed to decompress chunk {} in {}", i, path.display()))?;

        let mut value: Value = fastnbt::from_bytes(&uncompressed).with_context(|| {
            format!(
                "Failed to parse NBT data for chunk {} in {}",
                i,
                path.display()
            )
        })?;

        let replacements = replace_in_value(&mut value, &args.old, &args.new);
        total_replacements += replacements;

        let payload = if replacements == 0 || args.dry_run {
            chunk_slice[0..4 + chunk_length].to_vec()
        } else {
            let serialized =
                fastnbt::to_bytes(&value).context("Failed to encode modified chunk NBT")?;
            let recompressed =
                recompress_chunk(compression_type, &serialized).with_context(|| {
                    format!(
                        "Failed to recompress modified chunk {} in {}",
                        i,
                        path.display()
                    )
                })?;
            let mut payload = Vec::with_capacity(recompressed.len() + 5);
            let total_len = (recompressed.len() + 1) as u32;
            payload.extend_from_slice(&total_len.to_be_bytes());
            payload.push(compression_type);
            payload.extend_from_slice(&recompressed);
            payload
        };

        chunks[i] = Some(ChunkEntry { payload });
    }

    if total_replacements == 0 || args.dry_run {
        return Ok((total_replacements, false));
    }

    let mut output = vec![0u8; SECTOR_BYTES * 2];
    for (i, ts) in timestamps.iter().enumerate() {
        let idx = SECTOR_BYTES + i * 4;
        output[idx..idx + 4].copy_from_slice(&ts.to_be_bytes());
    }

    let mut current_sector = 2u32;
    for (i, entry) in chunks.into_iter().enumerate() {
        if let Some(chunk) = entry {
            let sector_count = ((chunk.payload.len() + SECTOR_BYTES - 1) / SECTOR_BYTES) as u32;
            if sector_count == 0 || sector_count > 255 {
                bail!(
                    "{} chunk {} requires invalid sector count {} (payload {} bytes)",
                    path.display(),
                    i,
                    sector_count,
                    chunk.payload.len()
                );
            }

            write_offset(&mut output, i, current_sector, sector_count);

            output.extend_from_slice(&chunk.payload);
            let used = chunk.payload.len();
            let padding = sector_count as usize * SECTOR_BYTES - used;
            if padding > 0 {
                output.extend(std::iter::repeat(0u8).take(padding));
            }
            current_sector += sector_count;
        }
    }

    std::fs::write(path, output)
        .with_context(|| format!("Failed to write rebuilt region {}", path.display()))?;

    Ok((total_replacements, true))
}

fn decompress_chunk(compression: u8, data: &[u8]) -> Result<Vec<u8>> {
    match compression {
        1 => decompress_gzip(data),
        2 => decompress_zlib(data),
        3 => Ok(data.to_vec()),
        other => bail!("Unsupported compression type {}", other),
    }
}

fn recompress_chunk(compression: u8, data: &[u8]) -> Result<Vec<u8>> {
    match compression {
        1 => compress_gzip(data),
        2 => compress_zlib(data),
        3 => Ok(data.to_vec()),
        other => bail!("Unsupported compression type {}", other),
    }
}

fn write_offset(header: &mut Vec<u8>, idx: usize, offset: u32, sectors: u32) {
    let base = idx * 4;
    let offset_bytes = [
        ((offset >> 16) & 0xFF) as u8,
        ((offset >> 8) & 0xFF) as u8,
        (offset & 0xFF) as u8,
        sectors as u8,
    ];
    header[base..base + 4].copy_from_slice(&offset_bytes);
}

fn replace_in_value(value: &mut Value, old: &str, new: &str) -> u64 {
    match value {
        Value::String(s) => replace_in_string(s, old, new),
        Value::List(list) => list.iter_mut().map(|v| replace_in_value(v, old, new)).sum(),
        Value::Compound(map) => map
            .values_mut()
            .map(|v| replace_in_value(v, old, new))
            .sum(),
        _ => 0,
    }
}

fn replace_in_string(target: &mut String, old: &str, new: &str) -> u64 {
    if old.is_empty() {
        return 0;
    }
    let occurrences = target.matches(old).count() as u64;
    if occurrences > 0 {
        *target = target.replace(old, new);
    }
    occurrences
}
