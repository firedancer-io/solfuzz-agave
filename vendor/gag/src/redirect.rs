use std::any::Any;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use filedescriptor::{AsRawFileDescriptor, FileDescriptor, StdioDescriptor};

static REDIRECT_FLAGS: [AtomicBool; 3] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

pub struct RedirectError<F> {
    pub error: io::Error,
    pub file: F,
}

impl<F> From<RedirectError<F>> for io::Error {
    fn from(err: RedirectError<F>) -> io::Error {
        err.error
    }
}

impl<F: Any> ::std::error::Error for RedirectError<F> {
    fn description(&self) -> &str {
        self.error.description()
    }
    fn cause(&self) -> Option<&::std::error::Error> {
        Some(&self.error)
    }
}

impl<F> ::std::fmt::Display for RedirectError<F> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        self.error.fmt(fmt)
    }
}

impl<F> ::std::fmt::Debug for RedirectError<F> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        self.error.fmt(fmt)
    }
}

/// Redirect stderr/stdout to a file.
pub struct Redirect<F> {
    #[allow(dead_code)]
    fds: RedirectFds,
    file: F,
}

// Separate struct so we can destruct the redirect and drop the file descriptors.
struct RedirectFds {
    std_fd: FileDescriptor,
    stdio: StdioDescriptor,
}

impl RedirectFds {
    fn make<F: AsRawFileDescriptor>(file: &F, stdio: StdioDescriptor) -> io::Result<RedirectFds> {
        if REDIRECT_FLAGS[stdio as usize].fetch_or(true, Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Redirect already exists.",
            ));
        }

        let std_fd = FileDescriptor::redirect_stdio(file, stdio)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;

        // Dropping this will redirect stdio back to original std_fd
        Ok(RedirectFds { std_fd, stdio })
    }
}

impl Drop for RedirectFds {
    fn drop(&mut self) {
        let _ = FileDescriptor::redirect_stdio(&self.std_fd, self.stdio);
        REDIRECT_FLAGS[self.stdio as usize].store(false, Ordering::Relaxed);
    }
}

impl<F> Redirect<F>
where
    F: AsRawFileDescriptor,
{
    fn make(file: F, stdio: StdioDescriptor) -> Result<Self, RedirectError<F>> {
        let fds = match RedirectFds::make(&file, stdio) {
            Ok(fds) => fds,
            Err(error) => return Err(RedirectError { error, file }),
        };
        Ok(Redirect { fds, file })
    }
    /// Redirect stdout to `file`.
    pub fn stdout(file: F) -> Result<Self, RedirectError<F>> {
        Redirect::make(file, StdioDescriptor::Stdout)
    }
    /// Redirect stderr to `file`.
    pub fn stderr(file: F) -> Result<Self, RedirectError<F>> {
        Redirect::make(file, StdioDescriptor::Stderr)
    }

    /// Extract inner file object.
    pub fn into_inner(self) -> F {
        self.file
    }
}
