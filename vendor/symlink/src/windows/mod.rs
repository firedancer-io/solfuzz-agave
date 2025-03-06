pub use std::os::windows::fs::{symlink_file, symlink_dir};
pub use std::fs::remove_dir as remove_symlink_dir;
use std::fs;
use std::io::{self, Error};
use std::mem;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::raw::HANDLE;
use std::path::Path;
use std::ptr;

mod c;

#[inline]
pub fn symlink_auto<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
    if fs::metadata(src.as_ref())?.is_dir() {
        symlink_dir(src.as_ref(), dst.as_ref())
    } else {
        symlink_file(src.as_ref(), dst.as_ref())
    }
}

#[inline]
pub fn remove_symlink_auto<P: AsRef<Path>>(path: P) -> io::Result<()> {
    // Ideally we’d be able to do fs::metadata(path.as_ref())?.file_type().{is_symlink_dir,
    // is_symlink}() or similar, but the standard library doesn’t expose that; really, we care
    // about whether the internal FileType object is a SymlinkFile or a SymlinkDir, but that’s not
    // exposed in any way, so ☹. Instead, we copy all that mess of code and call the Windows API
    // directly ourselves. Icky, isn’t it? (The alternative is copying the struct and transmuting;
    // that’s even more icky, though quite a bit shorter.)
    match symlink_type(path.as_ref())? {
        SymlinkType::Dir => fs::remove_dir(path),
        SymlinkType::File => fs::remove_file(path),
        SymlinkType::Not => Err(io::Error::new(io::ErrorKind::InvalidInput,
                                               "path is not a symlink")),
    }
}

pub enum SymlinkType {
    Not,
    File,
    Dir,
}

// Taken from rust/src/libstd/sys/windows/mod.rs
fn to_u16s<S: AsRef<OsStr>>(s: S) -> io::Result<Vec<u16>> {
    let mut encoded: Vec<u16> = s.as_ref().encode_wide().collect();
    if encoded.iter().any(|&u| u == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                  "strings passed to the Windows API cannot contain NULs"));
    }
    encoded.push(0);
    Ok(encoded)
}

// Drawn from rust/src/libstd/sys/windows/fs.rs; derived from stat(path) and File::open(path,
// opts).file_attr().file_type().{is_symlink, is_symlink_dir}().
pub fn symlink_type(path: &Path) -> io::Result<SymlinkType> {
    // Derived from File::file_attr, FileAttr::file_type, File::reparse_point, FileType::new,
    // FileType::is_symlink and FileType::is_symlink_dir (all from libstd/sys/windows/fs.rs).
    fn symlink_type(handle: HANDLE) -> io::Result<SymlinkType> {
        unsafe {
            let mut info: c::BY_HANDLE_FILE_INFORMATION = mem::zeroed();
            if c::GetFileInformationByHandle(handle, &mut info) == 0 {
                return Err(io::Error::last_os_error());
            }
            if info.dwFileAttributes & c::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                let mut space = [0; c::MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
                let mut bytes = 0;
                if c::DeviceIoControl(handle,
                                    c::FSCTL_GET_REPARSE_POINT,
                                    ptr::null_mut(),
                                    0,
                                    space.as_mut_ptr() as *mut _,
                                    space.len() as c::DWORD,
                                    &mut bytes,
                                    ptr::null_mut()) != 0 {
                    let buf = &*(space.as_ptr() as *const c::REPARSE_DATA_BUFFER);
                    return Ok(match (info.dwFileAttributes & c::FILE_ATTRIBUTE_DIRECTORY != 0,
                                    info.dwFileAttributes & c::FILE_ATTRIBUTE_REPARSE_POINT != 0,
                                    buf.ReparseTag) {
                        (_, false, _) => SymlinkType::Not,
                        (false, true, c::IO_REPARSE_TAG_SYMLINK) => SymlinkType::File,
                        (true, true, c::IO_REPARSE_TAG_SYMLINK) => SymlinkType::Dir,
                        (true, true, c::IO_REPARSE_TAG_MOUNT_POINT) => SymlinkType::Dir,
                        (_, true, _) => SymlinkType::Not,
                    });

                }
            }
            Ok(SymlinkType::Not)
        }
    }

    let path = to_u16s(path)?;
    let handle = unsafe {
        c::CreateFileW(path.as_ptr(),
                       0,
                       c::FILE_SHARE_READ | c::FILE_SHARE_WRITE | c::FILE_SHARE_DELETE,
                       ptr::null_mut(),
                       c::OPEN_EXISTING,
                       c::FILE_FLAG_BACKUP_SEMANTICS,
                       ptr::null_mut())
    };
    if handle == c::INVALID_HANDLE_VALUE {
        Err(Error::last_os_error())
    } else {
        let out = symlink_type(handle);
        unsafe { let _ = c::CloseHandle(handle); }
        out
    }
}
