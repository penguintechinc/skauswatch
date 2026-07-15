//! Generated gRPC types for the skauswatch wire contracts. Phase 2 moves
//! the v1 `.proto` files into `proto/{manager,s3scan,pki}/v1/` and wires
//! `tonic-build` codegen here. Proto **package names stay unchanged**
//! (`skauswatch.manager`, `skauswatch.s3scan`, `skauswatch.pki`) — the
//! package is part of the gRPC method path and fielded v1 EDR agents must
//! keep working against the v2 manager.
//!
//! A `buf breaking` CI gate guards these contracts against accidental
//! wire-incompatible edits.
