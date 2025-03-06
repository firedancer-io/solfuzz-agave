use std::io::{self, Read, Write};
use BufferRedirect;

/// Hold output until dropped. On drop, the held output is sent to the stdout/stderr.
///
/// Note: This will ignore IO errors when printing held output.
pub struct Hold {
    buf_redir: Option<BufferRedirect>,
    is_stdout: bool,
}

impl Hold {
    /// Hold stderr output.
    pub fn stderr() -> io::Result<Hold> {
        Ok(Hold {
            buf_redir: Some(BufferRedirect::stderr()?),
            is_stdout: false,
        })
    }

    /// Hold stdout output.
    pub fn stdout() -> io::Result<Hold> {
        Ok(Hold {
            buf_redir: Some(BufferRedirect::stdout()?),
            is_stdout: true,
        })
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        fn read_into<R: Read, W: Write>(mut from: R, mut to: W) {
            // TODO: use sendfile?
            let mut buf = [0u8; 4096];
            loop {
                // Ignore errors
                match from.read(&mut buf) {
                    Ok(0) => break,
                    Ok(size) => {
                        if to.write_all(&buf[..size]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Just in case...
            let _ = to.flush();
        }

        let from = self.buf_redir.take().unwrap().into_inner();
        // Ignore errors.
        if self.is_stdout {
            let stdout = io::stdout();
            read_into(from, stdout.lock());
        } else {
            let stderr = io::stderr();
            read_into(from, stderr.lock());
        }
    }
}
