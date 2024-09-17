# halo2wrong

`halo2wrong` consist of a simple PLONK gate and non native arithmetic based applications. Any crate here may use either [zcash/halo2](https://github.com/zcash/halo2) or [privacy-scaling-explorations/halo2](https://github.com/privacy-scaling-explorations/halo2) which is a fork of original halo2 library that replaces commitment scheme from IPA to KZG.

* `maingate` includes a 4 width and a 5 width standart-like PLONK gate.
* `integer` implements non native field arithemetic often called big integer arithmetic.
* `ecc` constraints elliptic curve operations ie. addition, multiplication point assignments.
* `ecdsa` is the first application that uses `halo2wrong` stack and constaints ECDSA signature verification.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
