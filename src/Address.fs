module LitecoinMultisig.Address

open Fable.Core
open LitecoinMultisig.Types

type private Bech32 =
    abstract toWords: bytes: byte[] -> obj
    abstract encode: prefix: string * words: obj -> string

[<Import("bech32", "@scure/base")>]
let private bech32 : Bech32 = jsNative

type private Base58Check =
    abstract encode: data: byte[] -> string
    abstract decode: encoded: string -> byte[]

[<Import("base58check", "@scure/base")>]
let private base58checkFactory : (byte[] -> byte[]) -> Base58Check = jsNative

let private b58check = base58checkFactory Crypto.sha256

[<Emit("[0, ...$0]")>]
let private withWitnessV0 (words: obj) : obj = jsNative

let private prefixed (prefix: byte) (payload: byte[]) : byte[] =
    Crypto.concatBytes [| [| prefix |]; payload |]

/// P2SH address: base58check(scriptHashPrefix ‖ hash160(redeemScript))
let p2shAddress (network: Network) (redeemScript: byte[]) : string =
    let p = networkParams network
    b58check.encode (prefixed p.ScriptHash (Crypto.hash160 redeemScript))

/// P2WSH address: bech32, witness v0, program = sha256(witnessScript)
let p2wshAddress (network: Network) (witnessScript: byte[]) : string =
    let p = networkParams network
    bech32.encode (p.Bech32Hrp, withWitnessV0 (bech32.toWords (Crypto.sha256 witnessScript)))

/// BIP141 nested redeem script: OP_0 PUSH32 sha256(witnessScript)
let p2shP2wshRedeemScript (witnessScript: byte[]) : byte[] =
    Crypto.concatBytes [| [| 0x00uy; 0x20uy |]; Crypto.sha256 witnessScript |]

let p2shP2wshAddress (network: Network) (witnessScript: byte[]) : string =
    p2shAddress network (p2shP2wshRedeemScript witnessScript)

/// Address for an m-of-n multisig wallet from cosigner pubkeys (BIP67 sort applied).
let multisigAddress (network: Network) (scriptType: ScriptType) (m: int) (pubkeys: byte[][]) : string =
    let script = Script.multisigScript m pubkeys
    match scriptType with
    | P2SH -> p2shAddress network script
    | P2WSH -> p2wshAddress network script
    | P2SH_P2WSH -> p2shP2wshAddress network script

/// Legacy single-sig P2PKH address.
let p2pkhAddress (network: Network) (pubkey: byte[]) : string =
    let p = networkParams network
    b58check.encode (prefixed p.PubKeyHash (Crypto.hash160 pubkey))

/// Native-segwit single-sig P2WPKH — default for free-tier wallets.
let p2wpkhAddress (network: Network) (pubkey: byte[]) : string =
    let p = networkParams network
    bech32.encode (p.Bech32Hrp, withWitnessV0 (bech32.toWords (Crypto.hash160 pubkey)))
