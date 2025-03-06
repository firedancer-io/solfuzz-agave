// Creates and error for the current crate, aliases Result to use the new error and defines a from! macro to use for converting to
// the local error type.
/// # Example
/// ```
/// use std::fs;
/// use simpl::err;
///
/// err!(ExampleError,
///     {
///         Io@std::io::Error;
///     });
///
/// fn main() -> Result<()> {
///     fs::create_dir("test")?;
///     fs::remove_dir_all("test")?;
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! err {
    ($i: ident, {$($j: ident@$t: ty;)*}) => {
        #[derive(Debug)]
        enum Errs {
            $( $j($t)),*
        }

        impl std::error::Error for Errs {}

        impl core::fmt::Display for Errs {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                match self {
                    $(
                        Errs::$j(t) => {
                            write!(f, "{}", t)
                        }
                    ),*
                }
            }
        }

        #[derive(Debug)]
        pub struct $i {
            pub description: Option<String>,
            pub data: Option<String>,
            source: Option<Errs>
        }

        impl std::error::Error for $i {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self.source {
                    Some(ref source) => Some(source),
                    None => None
                }
            }
        }

        impl std::convert::From<&str> for $i {
            fn from(str: &str) -> Self {
                $i {
                    description: Some(str.to_string()),
                    data: None,
                    source: None
                }
            }
        }

        impl core::fmt::Display for $i {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                match self.description.as_ref() {
                    Some(err) => write!(f, "{}", err),
                    None => write!(f, "An unknown error has occurred!"),
                }
            }
        }
        pub type Result<T, E = $i> = std::result::Result<T, E>;

        $(
            impl std::convert::From<$t> for $i {
                fn from(e: $t) -> $i {
                    $i {
                        description: Some(String::from(format!("{}", e))),
                        data: None,
                        source: Some(Errs::$j(e))
                    }
                }
            }
         )*
    };
}

#[cfg(test)]
mod tests {
    use std::fs;
    super::err!(TestError,
        {
            Io@std::io::Error;
        }
    );

    #[test]
    #[should_panic]
    fn should_fail_wrapper() {
        fn should_fail() -> Result<()> {
            fs::create_dir("test_fail/test")?;
            Ok(())
        }

        should_fail().unwrap();
    }

    #[test]
    fn should_succeed() -> Result<()> {
        fs::create_dir("test_dir")?;
        fs::remove_dir_all("test_dir")?;
        Ok(())
    }
}
