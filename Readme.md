# ttrss_api

"Tiny Tiny RSS is a free and open source web-based news feed (RSS/Atom) reader and aggregator." This is a Rust crate built around the [TinyTinyRSS API](https://git.tt-rss.org/git/tt-rss/wiki/ApiReference).

This crate tracks to the most recent version of TTRSS.

Visit [crates.io](https://crates.io/crates/ttrss_api/) or [docs.rs](https://docs.rs/ttrss_api/) for more info.


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
ttrss_api = "0.0.1"
```

Then add this to your crate:

```rust
extern crate ttrss_api;
```

To use:

```rust

fn main() {
    let apilevel: Option<ApiLevel> = match get_api_level().expect("Failed to get response").content {
        Content::GetApiLevel(x) => { Some(x) },
        _ => None,
    };
    println!("api level {:?}", apilevel.unwrap());
```

## Compatibility

The minimum Rust version supported is 1.43.1.


## Contribution

Feel free to submit PRs or issues for suggestions, bugs, or feedback.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.


## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
