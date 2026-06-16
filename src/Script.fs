module LitecoinMultisig.Script

/// Lexicographic (byte-wise) comparison used by BIP67.
let compareBytes (a: byte[]) (b: byte[]) : int =
    let len = min a.Length b.Length
    let mutable result = 0
    let mutable i = 0
    while result = 0 && i < len do
        result <- compare a.[i] b.[i]
        i <- i + 1
    if result <> 0 then result else compare a.Length b.Length

/// BIP67: deterministic public-key ordering. Non-optional for all multisig scripts.
let sortPubKeysBip67 (pubkeys: byte[][]) : byte[][] =
    pubkeys |> Array.sortWith compareBytes

[<Literal>]
let private OP_CHECKMULTISIG = 0xAEuy

let private opN (n: int) : byte = byte (0x50 + n)

/// Build an m-of-n multisig script from 33-byte compressed public keys.
/// Keys are BIP67-sorted internally; callers never control on-chain key order.
let multisigScript (m: int) (pubkeys: byte[][]) : byte[] =
    let n = pubkeys.Length
    if m < 1 || m > n then failwith $"invalid quorum: {m} of {n}"
    if n > 15 then failwith "at most 15 cosigners per script"
    for pk in pubkeys do
        if pk.Length <> 33 then failwith "public keys must be 33-byte compressed"
    let sorted = sortPubKeysBip67 pubkeys
    let script = Array.zeroCreate<byte> (3 + n * 34)
    script.[0] <- opN m
    let mutable offset = 1
    for pk in sorted do
        script.[offset] <- byte pk.Length
        Array.blit pk 0 script (offset + 1) pk.Length
        offset <- offset + 1 + pk.Length
    script.[offset] <- opN n
    script.[offset + 1] <- OP_CHECKMULTISIG
    script
