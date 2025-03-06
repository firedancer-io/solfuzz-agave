Redirect and/or gag stdout/stderr.

[![Build Status](https://travis-ci.org/Stebalien/gag-rs.svg?branch=master)](https://travis-ci.org/Stebalien/gag-rs)

Documentation (with examples): https://docs.rs/gag/

# Limitations

* Won't work if something else has called `std::io::set_print` (currently
  unstable). Unfortunately, this function doesn't actually redirect the stdio
  file descriptor, it just replaces the `std::io::stdout` writer.
* Won't work in rust test cases. The rust test cases use `std::io::set_print` to
  redirect stdout. You can get around this though by using the `--nocapture` argument
  when running your tests.

# TODO:

* General:
  * Better error handling?
* Redirect:
  * Be generic over references. That is, accept both a reference to an AsRawFd or
    an AsRawFd. Unfortunately, I don't know if this is even possible. Borrow
    doesn't work because I really want the following constraint:
    `impl<F> Redirect<F> where F: BorrowMut<T>, T: AsMut<AsRawFd>` so I can write
    `file.borrow_mut().as_mut()` but that would be ambiguous...
* Buffer:
  * Deallocate the buffer as it is read (FALLOC_FL_PUNCH_HOLE) if possible.
