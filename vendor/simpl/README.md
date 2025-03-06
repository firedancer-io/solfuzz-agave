# simplerr

Zero dependency error handling.

## Usage 

```toml
[dependancies]
simpl = 0.1.0
```

```rust
use std::fs;
use simpl::err;

err!(ExampleError,
    {
        Io@std::io::Error;
    });

fn main() -> Result<()> {
    fs::create_dir("test")?;
    fs::remove_dir_all("test")?;
    Ok(())
}
```
