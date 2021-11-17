use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum MemHackError {
    CreateHookError,
    MemoryReadError {
        address: usize,
        bytes_to_read: usize,
    },
    MemoryWriteError {
        address: usize,
        bytes_written: usize,
    },
    ModuleNotFound (String),
}

impl Error for MemHackError {}

impl Display for MemHackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemHackError::CreateHookError => write!(f, "Failed to create MemHook"),
            MemHackError::MemoryReadError {
                address,
                bytes_to_read,
            } => write!(f, "Failed to read {} bytes at {:x}", bytes_to_read, address),
            MemHackError::MemoryWriteError {
                address,
                bytes_written,
            } => write!(
                f,
                "Failed to write {} bytes at {:x}",
                bytes_written, address
            ),
            MemHackError::ModuleNotFound(mod_name) => write!(f, "Failed to find module '{}'", mod_name),
        }
    }
}
