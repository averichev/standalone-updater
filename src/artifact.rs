use crate::{Result, UpdateError};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

pub(crate) fn verify_elf(file: &mut File, target: &str, size: u64) -> Result<()> {
    let invalid = || UpdateError::Integrity("повреждённый ELF или неверная архитектура");
    if size < 64 || file.metadata()?.len() != size {
        return Err(invalid());
    }
    let mut header = [0_u8; 64];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header).map_err(|_| invalid())?;
    let u16_at = |offset| u16::from_le_bytes(header[offset..offset + 2].try_into().unwrap());
    let u64_at = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
    let machine = match target {
        "linux-x86_64" => 62,
        "linux-aarch64" => 183,
        _ => return Err(invalid()),
    };
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || u16_at(18) != machine
        || ![2, 3].contains(&u16_at(16))
        || u16_at(52) != 64
        || header[20..24] != [1, 0, 0, 0]
    {
        return Err(invalid());
    }
    let offset = u64_at(32);
    let entry = u64_at(24);
    let count = u16_at(56) as u64;
    let entry_size = u16_at(54) as u64;
    if count == 0
        || count > 1024
        || entry_size != 56
        || offset < 64
        || offset
            .checked_add(count * entry_size)
            .is_none_or(|end| end > size)
    {
        return Err(invalid());
    }
    let mut executable_entry = false;
    file.seek(SeekFrom::Start(offset))?;
    for _ in 0..count {
        let mut segment = [0_u8; 56];
        file.read_exact(&mut segment).map_err(|_| invalid())?;
        let u32_at = |offset| u32::from_le_bytes(segment[offset..offset + 4].try_into().unwrap());
        let u64_at = |offset| u64::from_le_bytes(segment[offset..offset + 8].try_into().unwrap());
        let (kind, flags, offset, address, length, memory) = (
            u32_at(0),
            u32_at(4),
            u64_at(8),
            u64_at(16),
            u64_at(32),
            u64_at(40),
        );
        if offset.checked_add(length).is_none_or(|end| end > size) || kind == 1 && length > memory {
            return Err(invalid());
        }
        if kind == 1
            && flags & 1 != 0
            && entry >= address
            && address.checked_add(memory).is_some_and(|end| entry < end)
        {
            executable_entry = true;
        }
    }
    if !executable_entry {
        return Err(invalid());
    }
    Ok(())
}
