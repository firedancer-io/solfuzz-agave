use redirect::Redirect;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;

// Helper function for opening /dev/null in unix or NUL on windows
fn null() -> io::Result<File> {
    #[cfg(windows)]
    return OpenOptions::new().write(true).open("NUL");

    #[cfg(unix)]
    return OpenOptions::new().write(true).open("/dev/null");
}

/// Discard output until dropped.
pub struct Gag(Redirect<File>);

impl Gag {
    /// Discard stdout until dropped.
    pub fn stdout() -> io::Result<Gag> {
        Ok(Gag(Redirect::stdout(null()?)?))
    }
    /// Discard stderr until dropped.
    pub fn stderr() -> io::Result<Gag> {
        Ok(Gag(Redirect::stderr(null()?)?))
    }
}
