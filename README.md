# Cobweb
Cobweb is a Rust library for creating fully asynchronous, encrypted VPNs, focused on simplicity and security. It supports both Mac and Linux - Windows support is a long-term goal but not planned.

Check out the documentation and examples for more info on how to use the library.

Cobweb is licensed under AGPLv3 to make sure that is free software and stays as free software. If you want a relicensed version for your project, email me and we (the contributers) will talk with you.

## Examples
Check the `examples` directory in the repository for example VPN client and server implementations.

## Next Release
Cobweb is currently in its `0.2.0` release - it provides enough features and documentation to be used powerfully, but lacks planned features, could use some better error handling and is not thoroughly tested. Use at your own risk.

`0.2.1` will see the first release of the optional `async-await-preview` feature to the crate. This flag will give access to code based on the upcoming `std::Future` and async/await APIs. Once those APIs become stable, the code based on the `futures` crate will be deprecated and moved under an optional `old-futures` flag, and Cobweb will see its `0.3.0` release.
