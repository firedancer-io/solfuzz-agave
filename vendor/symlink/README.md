# `symlink`: create (and delete) symlinks in a cross-platform manner

[![Build Status](https://gitlab.com/chris-morgan/symlink/badges/master/build.svg)](https://gitlab.com/chris-morgan/symlink/commits/master)

Rust’s standard library exposes platform-specific ways to create symlinks:

- On Windows, `std::os::windows::fs::{symlink_file, symlink_dir}` (because Windows does file and directory symlinks differently);
- On Unixy platforms and Redox, `std::os::unix::fs::symlink` (because they don’t care about whether it’s a file or a directory).

The situation is similar when removing symlinks: on Unixy platforms all symlinks are files and must be removed with `std::fs::remove_file`, but on Windows directory symlinks must be removed with `std::fs::remove_dir` instead.

This is all a pain: as soon as you touch symlinks for Unix you need to add in lots of `#[cfg]` branches and other such messy things, or else lose Windows support for no good reason.

Enter the `symlink` crate. This crate gives you six cross-platform functions instead:

- `symlink_file`, which creates a file symlink on Windows and a common-or-garden symlink on other platforms;
- `symlink_dir`, which creates a directory symlink on Windows and a perfectly ordinary symlink on other platforms;
- `symlink_auto`, which creates a file or directory symlink on Windows, depending on an examination of the destination, and a perfectly ordinary symlink on other platforms;
- `remove_symlink_file`, which removes a file symlink on Windows and a common-or-garden symlink on other platforms;
- `remove_symlink_dir`, which removes a directory symlink on Windows and a perfectly ordinary symlink on other platforms;
- `remove_symlink_auto`, which removes a file or directory symlink on Windows, depending on an examination of the path, and a perfectly ordinary symlink on other platforms.

“What about `std::fs::soft_link`?” I hear you say. Yeah, that one got deprecated in Rust 1.1.0 because it didn’t do anything clever on Windows, it just created a file symlink, which is often wrong. `symlink_auto` creates a file *or* directory symlink, depending on what the target is. (Unlike `symlink_file` and `symlink_dir`, it returns an error if the destination doesn’t exist or can’t be statted.)

And there’s no good way to delete a symlink at all.

So that’s why this crate exists.

## Best practices

You should generally avoid `symlink_auto` and `remove_symlink_auto`, preferring to use the more specific `symlink_file` or `symlink_dir` and `remove_symlink_file` or `remove_symlink_dir`, whichever seems appropriate for what you’re doing. (In real life you almost always know whether you’re making a file or a directory symlink, so say it in the code!)

**Make sure you use absolute paths for the destination.** I haven’t tested whether relative paths are treated consistently across platforms yet (whether they’re relative to the working directory or the symlink source path). TODO!

## Caution: this isn’t as useful as it looks

So now you can create or delete symlinks, right? Not so fast. Although Windows supports symlinks from Windows Vista onwards, it was viewed as a security or compatibility or something risk, and so prior to the Windows 10 Creators Update (due by mid-2017; currently available through the Windows Insider Program) it requires a special privilege, which basically means you’ve got to run a program as admin for it to be allowed to manipulate symlinks.

Also [Rust PR #38921](https://github.com/rust-lang/rust/pull/38921) needs to land before unprivileged symlink creation will work on the Windows 10 Creators Update. So we’re talking Rust 1.16 as the earliest.

## My goal: integration with Rust

I would like to merge this into libstd in some form, because the symlink manipulation support in the standard library at present is hopeless for cross-platformness. I haven’t written an RFC yet; it should definitely start as a separate crate (that’s what this is). Here are some of my thoughts:

**Concerning `symlink_auto`**: it’s deliberately not named `symlink`; my hope is that people won’t just reach for it blindly but will think about what they are doing. A few things can happen to it (in my order of preference):

1. It can not exist. It’s really not *necessary*, and letting people be lazy isn’t always good. Encourage cross-platformness!
2. It can exist as `std::fs::symlink_auto`. The distinction is thus clear.
3. `std::fs::soft_link` can be undeprecated, with a change to its Windows semantics from “make a file symlink” to “make a file or directory symlink as appropriate, yielding an error if the destination doesn’t stat”.
4. `std::fs::soft_link` can be undeprecated, with a change to its Windows semantics from “make a file symlink” to “make a file or directory symlink as appropriate, going with a file symlink if the destination doesn’t stat”.
5. It can exist as `std::fs::symlink`. This is the obvious name, but as mentioned earlier encourages inefficient imprecision for Windows.

**Concerning `symlink_dir` and `symlink_file`**:

1. `std::fs::{symlink_file, symlink_dir}`, matching `symlink_auto` or nothing.

2. `std::fs::{soft_link_file, soft_link_dir}`, matching `soft_link` if it is undeprecated. But I don’t like the name “soft link,” anyway: no one calls them that, we all call them symlinks.

Note that despite the suggestions matching certain approaches for `symlink_auto`, the choices are still independent; there are ten viable combinations presented.

**Concerning `remove_*`**: I guess what’s done with the other three functions will guide what’s done with these three.

## Usage

Cargo all the way: it’s the [`symlink` crate on crates.io](http://crates.io/crates/symlink).

## Unsafe code in this library

On Windows only there is some unavoidable unsafe code in `remove_symlink_auto` to determine whether a symlink is a file symlink or a directory symlink, because this detail is not exposed in the standard library.

## Author

[Chris Morgan](http://chrismorgan.info/) ([chris-morgan](https://gitlab.com/chris-morgan)) is the primary author and maintainer of this library.

## License

This library is distributed under similar terms to Rust: dual licensed under the MIT license and the Apache license (version 2.0).

See LICENSE-APACHE, LICENSE-MIT, and COPYRIGHT for details.
