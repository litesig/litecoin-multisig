module LitecoinMultisig.Psbt

open System
open Fable.Core
open Fable.Core.JsInterop
open LitecoinMultisig.Types

// bitcoinjs-lib v6 expects Buffer (not plain Uint8Array) for script fields.
// Imported from the `buffer` npm package so the browser bundle gets the
// polyfill — the global Buffer only exists under Node.
[<Import("Buffer", "buffer")>]
let private BufferClass: obj = jsNative

let private toBuffer (bytes: byte[]) : byte[] = BufferClass?from bytes |> unbox

type Psbt =
    abstract addInput: input: obj -> Psbt
    abstract addOutput: output: obj -> Psbt
    abstract signInput: index: int * signer: obj -> Psbt
    abstract validateSignaturesOfInput: index: int * validator: Func<byte[], byte[], byte[], bool> -> bool
    abstract combine: other: Psbt -> Psbt
    abstract finalizeAllInputs: unit -> Psbt
    abstract extractTransaction: unit -> obj
    abstract toBase64: unit -> string

type private PsbtStatic =
    [<Emit("new $0({ network: $1 })")>]
    abstract create: network: obj -> Psbt
    [<Emit("$0.fromBase64($1, { network: $2 })")>]
    abstract fromBase64: data: string * network: obj -> Psbt

[<Import("Psbt", "bitcoinjs-lib")>]
let private PsbtJs : PsbtStatic = jsNative

/// bitcoinjs-lib network descriptor for Litecoin.
let bitcoinJsNetwork (network: Network) : obj =
    let p = networkParams network
    createObj [
        "messagePrefix" ==> "Litecoin Signed Message:\n"
        "bech32" ==> p.Bech32Hrp
        "bip32" ==> Bip32.bip32Versions network
        "pubKeyHash" ==> int p.PubKeyHash
        "scriptHash" ==> int p.ScriptHash
        "wif" ==> int p.WifPrefix
    ]

let create (network: Network) : Psbt =
    PsbtJs.create (bitcoinJsNetwork network)

let fromBase64 (network: Network) (data: string) : Psbt =
    PsbtJs.fromBase64 (data, bitcoinJsNetwork network)

let private p2wshScriptPubKey (witnessScript: byte[]) : byte[] =
    Crypto.concatBytes [| [| 0x00uy; 0x20uy |]; Crypto.sha256 witnessScript |]

let private p2shScriptPubKey (redeemScript: byte[]) : byte[] =
    Crypto.concatBytes [| [| 0xA9uy; 0x14uy |]; Crypto.hash160 redeemScript; [| 0x87uy |] |]

/// Add a segwit multisig input. `valueSats` is the UTXO amount in litoshis.
let addMultisigInput (scriptType: ScriptType) (witnessScript: byte[]) (txid: string) (vout: int) (valueSats: float) (psbt: Psbt) : Psbt =
    match scriptType with
    | P2WSH ->
        psbt.addInput (createObj [
            "hash" ==> txid
            "index" ==> vout
            "witnessUtxo" ==> createObj [
                "script" ==> toBuffer (p2wshScriptPubKey witnessScript)
                "value" ==> valueSats
            ]
            "witnessScript" ==> toBuffer witnessScript
        ])
    | P2SH_P2WSH ->
        let redeem = Address.p2shP2wshRedeemScript witnessScript
        psbt.addInput (createObj [
            "hash" ==> txid
            "index" ==> vout
            "witnessUtxo" ==> createObj [
                "script" ==> toBuffer (p2shScriptPubKey redeem)
                "value" ==> valueSats
            ]
            "redeemScript" ==> toBuffer redeem
            "witnessScript" ==> toBuffer witnessScript
        ])
    | P2SH ->
        failwith "legacy P2SH inputs need the full previous transaction; use addLegacyInput"

/// Add a legacy P2SH multisig input (requires the full previous transaction hex).
let addLegacyInput (redeemScript: byte[]) (prevTxHex: string) (txid: string) (vout: int) (psbt: Psbt) : Psbt =
    psbt.addInput (createObj [
        "hash" ==> txid
        "index" ==> vout
        "nonWitnessUtxo" ==> BufferClass?from (prevTxHex, "hex")
        "redeemScript" ==> toBuffer redeemScript
    ])

/// Add a single-sig P2WPKH input (free-tier wallets).
let addP2wpkhInput (pubkey: byte[]) (txid: string) (vout: int) (valueSats: float) (psbt: Psbt) : Psbt =
    let spk = Crypto.concatBytes [| [| 0x00uy; 0x14uy |]; Crypto.hash160 pubkey |]
    psbt.addInput (createObj [
        "hash" ==> txid
        "index" ==> vout
        "witnessUtxo" ==> createObj [ "script" ==> toBuffer spk; "value" ==> valueSats ]
    ])

let addOutput (address: string) (valueSats: float) (psbt: Psbt) : Psbt =
    psbt.addOutput (createObj [ "address" ==> address; "value" ==> valueSats ])

[<Import("address", "bitcoinjs-lib")>]
let private addressMod: obj = jsNative

let isValidAddress (network: Network) (address: string) : bool =
    try
        addressMod?toOutputScript (address, bitcoinJsNetwork network) |> ignore
        true
    with _ ->
        false

/// Sign input `index` with an unlocked address-level HD key.
let signInput (index: int) (key: Bip32.HDKey) (psbt: Psbt) : Psbt =
    let signer = createObj [
        "publicKey" ==> toBuffer key.publicKey
        "sign" ==> Func<byte[], byte[]>(fun hash -> toBuffer (key.sign hash))
    ]
    psbt.signInput (index, signer)

/// Validate every partial signature on the input with noble-secp256k1.
let validateSignatures (index: int) (psbt: Psbt) : bool =
    psbt.validateSignaturesOfInput (index, Func<_, _, _, _>(fun pubkey msghash signature ->
        Crypto.verifySignature signature msghash pubkey))

let combine (other: Psbt) (psbt: Psbt) : Psbt = psbt.combine other

let inputCount (psbt: Psbt) : int = (box psbt)?data?inputs?length

/// Lowest partial-signature count across inputs — the wallet's signing
/// progress is bounded by its least-signed input.
let signatureCount (psbt: Psbt) : int =
    let inputs: obj[] = (box psbt)?data?inputs
    if inputs.Length = 0 then
        0
    else
        inputs
        |> Array.map (fun input ->
            let sigs: obj[] = input?partialSig
            if isNullOrUndefined sigs then 0 else sigs.Length)
        |> Array.min

/// Sign every input that involves one of `account`'s keys, scanning
/// receive-chain indexes 0..maxIndex to find the right derivation. Works for
/// multisig (pubkey appears in witnessScript) and P2WPKH (pubkey hash in the
/// scriptPubKey). Returns the number of inputs signed.
let signWithAccount (account: Bip32.HDKey) (maxIndex: int) (psbt: Psbt) : int =
    let inputs: obj[] = (box psbt)?data?inputs
    let mutable signedCount = 0
    for i in 0 .. inputs.Length - 1 do
        let input = inputs.[i]
        let witnessScriptHex =
            let ws: byte[] = input?witnessScript
            if isNullOrUndefined ws then None else Some (Crypto.bytesToHex ws)
        let scriptPubKeyHex =
            let wu = input?witnessUtxo
            if isNullOrUndefined wu then None else Some (Crypto.bytesToHex (wu?script: byte[]))
        let mutable found = false
        let mutable j = 0
        while not found && j <= maxIndex do
            let key = account |> Bip32.deriveAddressKey 0 j
            let matches =
                match witnessScriptHex with
                | Some ws -> ws.Contains (Crypto.bytesToHex key.publicKey)
                | None ->
                    match scriptPubKeyHex with
                    | Some spk -> spk.Contains (Crypto.bytesToHex (Crypto.hash160 key.publicKey))
                    | None -> false
            if matches then
                found <- true
                try
                    signInput i key psbt |> ignore
                    signedCount <- signedCount + 1
                with _ ->
                    () // this key already signed the input
            j <- j + 1
    signedCount

let toBase64 (psbt: Psbt) : string = psbt.toBase64 ()

/// Finalize all inputs and return the raw transaction hex ready for broadcast.
let finalizeAndExtract (psbt: Psbt) : string =
    psbt.finalizeAllInputs () |> ignore
    let tx = psbt.extractTransaction ()
    let hex: string = tx?toHex ()
    hex
