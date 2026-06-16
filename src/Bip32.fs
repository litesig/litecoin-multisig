module LitecoinMultisig.Bip32

open Fable.Core
open Fable.Core.JsInterop
open LitecoinMultisig.Types

[<Import("wordlist", "@scure/bip39/wordlists/english")>]
let private englishWordlist : string[] = jsNative

[<Import("generateMnemonic", "@scure/bip39")>]
let private bip39Generate (wordlist: string[]) (strength: int) : string = jsNative

[<Import("validateMnemonic", "@scure/bip39")>]
let private bip39Validate (mnemonic: string) (wordlist: string[]) : bool = jsNative

[<Import("mnemonicToSeedSync", "@scure/bip39")>]
let private bip39ToSeedSync (mnemonic: string) (passphrase: string) : byte[] = jsNative

type HDKey =
    abstract derive: path: string -> HDKey
    abstract deriveChild: index: int -> HDKey
    abstract publicKey: byte[]
    abstract privateKey: byte[]
    abstract publicExtendedKey: string
    abstract privateExtendedKey: string
    abstract fingerprint: float
    abstract sign: hash: byte[] -> byte[]
    abstract wipePrivateData: unit -> HDKey

type private HDKeyStatic =
    abstract fromMasterSeed: seed: byte[] * versions: obj -> HDKey
    abstract fromExtendedKey: key: string * versions: obj -> HDKey

[<Import("HDKey", "@scure/bip32")>]
let private HDKeyJs : HDKeyStatic = jsNative

type MnemonicLength =
    | Words12
    | Words24

let generateMnemonic (length: MnemonicLength) : string =
    let strength = match length with Words12 -> 128 | Words24 -> 256
    bip39Generate englishWordlist strength

let validateMnemonic (mnemonic: string) : bool =
    bip39Validate mnemonic englishWordlist

let mnemonicToSeed (mnemonic: string) (passphrase: string) : byte[] =
    bip39ToSeedSync mnemonic passphrase

/// Extended-key version bytes: Ltub/Ltpv on mainnet, ttub/ttpv on testnet (SLIP-132).
let bip32Versions (network: Network) : obj =
    match network with
    | Mainnet -> createObj [ "public" ==> 0x019DA462; "private" ==> 0x019D9CFE ]
    | Testnet -> createObj [ "public" ==> 0x0436F6E1; "private" ==> 0x0436EF7D ]

let masterFromSeed (network: Network) (seed: byte[]) : HDKey =
    HDKeyJs.fromMasterSeed (seed, bip32Versions network)

let fromExtendedKey (network: Network) (key: string) : HDKey =
    HDKeyJs.fromExtendedKey (key, bip32Versions network)

/// BIP48 multisig account path: m/48'/coin'/account'/script'
let bip48Path (network: Network) (account: int) (scriptType: ScriptType) : string =
    let coin = match network with Mainnet -> 2 | Testnet -> 1
    let script =
        match scriptType with
        | P2SH -> 0
        | P2SH_P2WSH -> 1
        | P2WSH -> 2
    $"m/48'/{coin}'/{account}'/{script}'"

let deriveAccount (network: Network) (account: int) (scriptType: ScriptType) (master: HDKey) : HDKey =
    master.derive (bip48Path network account scriptType)

/// BIP84 account path for single-sig P2WPKH wallets: m/84'/coin'/account'
let bip84Path (network: Network) (account: int) : string =
    let coin = match network with Mainnet -> 2 | Testnet -> 1
    $"m/84'/{coin}'/{account}'"

let deriveSingleSigAccount (network: Network) (account: int) (master: HDKey) : HDKey =
    master.derive (bip84Path network account)

/// Derive the key for a receive (change=0) or change (change=1) address at `index`,
/// starting from an account-level node (our own xprv or a cosigner's xpub).
let deriveAddressKey (change: int) (index: int) (accountNode: HDKey) : HDKey =
    accountNode.deriveChild(change).deriveChild(index)
