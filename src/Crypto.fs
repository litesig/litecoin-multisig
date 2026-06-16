module LitecoinMultisig.Crypto

open Fable.Core

[<Import("sha256", "@noble/hashes/sha256")>]
let private nobleSha256 (data: byte[]) : byte[] = jsNative

[<Import("ripemd160", "@noble/hashes/ripemd160")>]
let private nobleRipemd160 (data: byte[]) : byte[] = jsNative

[<Import("bytesToHex", "@noble/hashes/utils")>]
let bytesToHex (bytes: byte[]) : string = jsNative

[<Import("hexToBytes", "@noble/hashes/utils")>]
let hexToBytes (hex: string) : byte[] = jsNative

[<Import("verify", "@noble/secp256k1")>]
let private nobleVerify (signature: byte[]) (msgHash: byte[]) (publicKey: byte[]) : bool = jsNative

let sha256 (data: byte[]) : byte[] = nobleSha256 data
let ripemd160 (data: byte[]) : byte[] = nobleRipemd160 data
let hash160 (data: byte[]) : byte[] = ripemd160 (sha256 data)
let sha256d (data: byte[]) : byte[] = sha256 (sha256 data)

/// Verify a 64-byte compact ECDSA signature against a 32-byte message hash
/// and a 33-byte compressed public key.
let verifySignature (signature: byte[]) (msgHash: byte[]) (publicKey: byte[]) : bool =
    nobleVerify signature msgHash publicKey

/// Concatenate byte chunks into a single Uint8Array.
let concatBytes (chunks: byte[][]) : byte[] =
    let total = chunks |> Array.sumBy (fun c -> c.Length)
    let out = Array.zeroCreate<byte> total
    let mutable offset = 0
    for c in chunks do
        Array.blit c 0 out offset c.Length
        offset <- offset + c.Length
    out
