// These are copied from libstd/sys/windows/c.rs out of necessity.
// Note that I *can’t* use the winapi crate only, apparently, as it curiously lacks
// REPARSE_DATA_BUFFER and MAXIMUM_REPARSE_DATA_BUFFER_SIZE (at 0.2.8, anyway). So I just threw in
// the towel and decided not to use kernel32-sys and winapi at all.

#![allow(non_snake_case, non_camel_case_types)]

use std::os::raw::{c_int, c_uint, c_ushort, c_ulong, c_void};
use std::os::windows::raw::HANDLE;

pub type WCHAR = u16;
pub type DWORD = c_ulong;
pub type BOOL = c_int;
pub type LPVOID = *mut c_void;
pub type LPDWORD = *mut DWORD;
pub type LPCWSTR = *const WCHAR;
pub type LPOVERLAPPED = *mut OVERLAPPED;
pub type LPBY_HANDLE_FILE_INFORMATION = *mut BY_HANDLE_FILE_INFORMATION;
pub type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;

pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x10;
pub const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x400;

pub const IO_REPARSE_TAG_SYMLINK: DWORD = 0xa000000c;
pub const IO_REPARSE_TAG_MOUNT_POINT: DWORD = 0xa0000003;

pub const FILE_SHARE_DELETE: DWORD = 0x4;
pub const FILE_SHARE_READ: DWORD = 0x1;
pub const FILE_SHARE_WRITE: DWORD = 0x2;

pub const OPEN_EXISTING: DWORD = 3;
pub const FILE_FLAG_BACKUP_SEMANTICS: DWORD = 0x02000000;

pub const INVALID_HANDLE_VALUE: HANDLE = !0 as HANDLE;

pub const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
pub const FSCTL_GET_REPARSE_POINT: DWORD = 0x900a8;

#[repr(C)]
pub struct BY_HANDLE_FILE_INFORMATION {
    pub dwFileAttributes: DWORD,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub dwVolumeSerialNumber: DWORD,
    pub nFileSizeHigh: DWORD,
    pub nFileSizeLow: DWORD,
    pub nNumberOfLinks: DWORD,
    pub nFileIndexHigh: DWORD,
    pub nFileIndexLow: DWORD,
}

#[repr(C)]
pub struct REPARSE_DATA_BUFFER {
    pub ReparseTag: c_uint,
    pub ReparseDataLength: c_ushort,
    pub Reserved: c_ushort,
    pub rest: (),
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

#[repr(C)]
pub struct OVERLAPPED {
    pub Internal: *mut c_ulong,
    pub InternalHigh: *mut c_ulong,
    pub Offset: DWORD,
    pub OffsetHigh: DWORD,
    pub hEvent: HANDLE,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

extern "system" {
    pub fn CreateFileW(lpFileName: LPCWSTR,
                       dwDesiredAccess: DWORD,
                       dwShareMode: DWORD,
                       lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
                       dwCreationDisposition: DWORD,
                       dwFlagsAndAttributes: DWORD,
                       hTemplateFile: HANDLE)
                       -> HANDLE;
    pub fn GetFileInformationByHandle(hFile: HANDLE,
                            lpFileInformation: LPBY_HANDLE_FILE_INFORMATION)
                            -> BOOL;
    pub fn DeviceIoControl(hDevice: HANDLE,
                           dwIoControlCode: DWORD,
                           lpInBuffer: LPVOID,
                           nInBufferSize: DWORD,
                           lpOutBuffer: LPVOID,
                           nOutBufferSize: DWORD,
                           lpBytesReturned: LPDWORD,
                           lpOverlapped: LPOVERLAPPED) -> BOOL;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
}
