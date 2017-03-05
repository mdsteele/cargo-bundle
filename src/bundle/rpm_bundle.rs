// For more information about the RPM file format, see http://rpm5.org/docs/api/pkgformat.html and
// http://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/pkgformat.html

use Settings;
use byteorder::{BigEndian, WriteBytesExt};
use cpio;
use libflate::gzip;
use md5;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::ops::Deref;
use std::path::PathBuf;

// Magic number identifying the file as an RPM file.
const RPM_MAGIC_NUMBER: &'static [u8] = &[0xED, 0xAB, 0xEE, 0xDB];
// What RPM format version we're generating (in this case, v3.0):
const RPM_MAJOR_VERSION: u8 = 3;
const RPM_MINOR_VERSION: u8 = 0;
// Value for "type" field (0 for binary packages, 1 for source packages):
const RPM_TYPE: u16 = 0;
// Value for "archnum" field, which is supposed to represent what architecture
// the package is for.  But apparently, almost nothing actually uses this, and
// packages for all architectures we care about (in particular, both i386 and
// x86_64) just use 1 here (http://stackoverflow.com/questions/39416934).
const RPM_ARCHNUM: u16 = 1;
// Value for "osnum" field, which is supposed to represent what OS the package
// is for.  Apparently the only valid value for this is 1 (Linux).
const RPM_OSNUM: u16 = 1;
// Value for "signature_type" field, which is supposed to indicate what kind of
// signature we're using.  For v3.0 packages, this must be 5 (header-style).
const RPM_SIGNATURE_TYPE: u16 = 5;
// Value for unused reserved field.
const RPM_RESERVED: &'static [u8] = &[0; 16];

// Magic number identifying the start of the header section.
const HEADER_MAGIC_NUMBER: &'static [u8] = &[0x8E, 0xAD, 0xE8, 0x01];
// Value for unused reserved field.
const HEADER_RESERVED: &'static [u8] = &[0; 4];
const HEADER_TYPE_INT32: u32 = 4;
const HEADER_TYPE_STRING: u32 = 6;
const HEADER_TYPE_BIN: u32 = 7;

// Header tags for the signature section:
const TAG_SIGNATURE_SIZE: u32 = 1000;
const TAG_SIGNATURE_MD5: u32 = 1004;

// Header tags for the headers section:
const TAG_RPM_NAME: u32 = 1000;
const TAG_RPM_VERSION: u32 = 1001;
const TAG_RPM_RELEASE: u32 = 1002;
const TAG_RPM_SUMMARY: u32 = 1004;
const TAG_RPM_DESCRIPTION: u32 = 1005;
const TAG_RPM_SIZE: u32 = 1009;
const TAG_RPM_URL: u32 = 1020;
const TAG_RPM_ARCH: u32 = 1022;
const TAG_RPM_PAYLOAD_FORMAT: u32 = 1124;
const TAG_RPM_PAYLOAD_COMPRESSOR: u32 = 1125;
const TAG_RPM_PAYLOAD_FLAGS: u32 = 1126;

enum HeaderValue {
    Int32(i32),
    String(String),
    Bin(Vec<u8>),
    I18nString(String)
}

impl HeaderValue {
    fn write(&self, tag: u32, index: &mut Vec<u8>, data: &mut Vec<u8>) -> io::Result<()> {
        index.write_u32::<BigEndian>(tag)?;
        fn align(alignment: usize, vec: &mut Vec<u8>) {
            let extra = vec.len() % alignment;
            if extra > 0 {
                vec.extend_from_slice(&vec![0; alignment - extra]);
            }
        }
        match self {
            &HeaderValue::Int32(value) => {
                align(4, data);
                index.write_u32::<BigEndian>(HEADER_TYPE_INT32)?;
                index.write_u32::<BigEndian>(data.len() as u32)?;
                index.write_u32::<BigEndian>(1)?;
                data.write_i32::<BigEndian>(value)?;
            }
            &HeaderValue::I18nString(ref value) |
            &HeaderValue::String(ref value) => {
                index.write_u32::<BigEndian>(HEADER_TYPE_STRING)?;
                index.write_u32::<BigEndian>(data.len() as u32)?;
                index.write_u32::<BigEndian>(1)?;
                data.write_all(value.as_bytes())?;
                data.write_u8(0)?;
            }
            &HeaderValue::Bin(ref value) => {
                index.write_u32::<BigEndian>(HEADER_TYPE_BIN)?;
                index.write_u32::<BigEndian>(data.len() as u32)?;
                index.write_u32::<BigEndian>(value.len() as u32)?;
                data.write_all(&value)?;
            }
        }
        Ok(())
    }
}

struct HeaderRecord {
    entries: Vec<(u32, HeaderValue)>
}

impl HeaderRecord {
    fn new() -> HeaderRecord {
        HeaderRecord { entries: Vec::new() }
    }

    fn add_int32(&mut self, tag: u32, value: i32) {
        self.entries.push((tag, HeaderValue::Int32(value)));
    }

    fn add_string(&mut self, tag: u32, value: &str) {
        self.entries.push((tag, HeaderValue::String(value.to_string())));
    }

    fn add_bin(&mut self, tag: u32, value: &[u8]) {
        self.entries.push((tag, HeaderValue::Bin(Vec::from(value))));
    }

    fn add_i18n_string(&mut self, tag: u32, value: &str) {
        self.entries.push((tag, HeaderValue::I18nString(value.to_string())));
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut index: Vec<u8> = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        for &(tag, ref value) in self.entries.iter() {
            value.write(tag, &mut index, &mut data)?;
        }
        writer.write_all(HEADER_MAGIC_NUMBER)?;
        writer.write_all(HEADER_RESERVED)?;
        writer.write_u32::<BigEndian>(self.entries.len() as u32)?;
        writer.write_u32::<BigEndian>(data.len() as u32)?;
        writer.write_all(&index)?;
        writer.write_all(&data)?;
        Ok(())
    }

    fn into_data(self) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.write(&mut data)?;
        Ok(data)
    }
}

pub fn bundle_project(settings: &Settings) -> ::Result<Vec<PathBuf>> {
    let binary_name = settings.cargo_settings.binary_name()?;
    let version_string = settings.version_string();
    let release = "0"; // TODO(mdsteele): Get real release number
    let arch = env::consts::ARCH; // TODO(mdsteele): Use binary arch rather than host arch

    let mut cpio_files: Vec<(String, File)> = Vec::new();
    cpio_files.push((format!("usr/bin/{}", binary_name), File::open(&settings.cargo_settings.binary_file)?));
    // TODO(mdsteele): Add other files
    let mut total_size = 0;
    let mut cpio_inputs: Vec<(cpio::NewcBuilder, File)> = Vec::new();
    for (name, file) in cpio_files.into_iter() {
        let metadata = file.metadata()?;
        total_size += metadata.len();
        let builder = cpio::NewcBuilder::new(&name);
        cpio_inputs.push((builder, file));
    }
    let cpio_path = settings.cargo_settings
        .project_out_directory
        .join(format!("{}_{}_{}.cpio", binary_name, version_string, arch));
    let compressed_cpio_size = {
        let cpio_file = File::create(&cpio_path)?;
        let gzip_encoder = gzip::Encoder::new(cpio_file)?;
        let gzip_encoder = cpio::write_cpio(cpio_inputs.into_iter(), gzip_encoder)?;
        let cpio_file = gzip_encoder.finish().into_result()?;
        cpio_file.metadata()?.len()
    };

    let mut headers = HeaderRecord::new();
    headers.add_string(TAG_RPM_NAME, &settings.bundle_name);
    headers.add_string(TAG_RPM_VERSION, version_string);
    headers.add_string(TAG_RPM_RELEASE, release);
    headers.add_i18n_string(TAG_RPM_SUMMARY, &settings.short_description());
    if let Some(desc) = settings.long_description() {
        headers.add_i18n_string(TAG_RPM_DESCRIPTION, desc);
    }
    headers.add_int32(TAG_RPM_SIZE, total_size as i32);
    if !settings.cargo_settings.homepage.is_empty() {
        headers.add_string(TAG_RPM_URL, &settings.cargo_settings.homepage);
    }
    headers.add_string(TAG_RPM_ARCH, arch);
    headers.add_string(TAG_RPM_PAYLOAD_FORMAT, "cpio");
    headers.add_string(TAG_RPM_PAYLOAD_COMPRESSOR, "gzip");
    headers.add_string(TAG_RPM_PAYLOAD_FLAGS, "9"); // compression level

    let package_path = settings.cargo_settings
        .project_out_directory
        .join(format!("{}_{}_{}.rpm", binary_name, version_string, arch));
    let mut package_file = File::create(&package_path)?;
    package_file.write_all(RPM_MAGIC_NUMBER)?;
    package_file.write_u8(RPM_MAJOR_VERSION)?;
    package_file.write_u8(RPM_MINOR_VERSION)?;
    package_file.write_u16::<BigEndian>(RPM_TYPE)?;
    package_file.write_u16::<BigEndian>(RPM_ARCHNUM)?;
    {
        // The name field is always 66 bytes long.  The name itself must be at
        // most 65 bytes and null-terminated.
        let name = format!("{}-{}-{}", binary_name, version_string, release);
        let mut name: Vec<u8> = Vec::from(name.as_bytes());
        name.resize(65, 0);
        name.push(0);
        package_file.write_all(&name)?;
    }
    package_file.write_u16::<BigEndian>(RPM_OSNUM)?;
    package_file.write_u16::<BigEndian>(RPM_SIGNATURE_TYPE)?;
    package_file.write_all(RPM_RESERVED)?;
    let headers_data = headers.into_data()?;
    {
        let mut signature = HeaderRecord::new();
        signature.add_int32(TAG_SIGNATURE_SIZE,
                            headers_data.len() as i32 + compressed_cpio_size as i32);
        let mut hash = md5::Context::new();
        hash.consume(&headers_data);
        io::copy(&mut File::open(&cpio_path)?, &mut hash)?;
        signature.add_bin(TAG_SIGNATURE_MD5, hash.compute().deref());
        signature.write(&mut package_file)?;
    }
    package_file.write_all(&headers_data)?;
    io::copy(&mut File::open(&cpio_path)?, &mut package_file)?;
    Ok(vec![package_path])
}
