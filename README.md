# Cobweb

`cobweb` is a Rust library for creating encrypted VPNs, focused on simplicity and security.

Currently `cobweb` is in version 0.1.0, and it pretty much sucks. The APIs can be unwieldly, the error handling is minimal, and it is not well tested. Contributions are very welcome.

Check out the documentation and examples for more info on how to use the library.

`cobweb` is licensed under AGPLv3 to make sure that is free software and stays as free software. If you want a relicensed version for your project, email me and we (the contributers) will talk with you.

## Build
Building a crate that depends on `cobweb` will require the following flag to be set:

```
RUSTFLAGS=-Ctarget-feature=+aes,+ssse3
```
