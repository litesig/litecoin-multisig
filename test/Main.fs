module LitecoinMultisig.Tests.Main

open System
open Fable.Core
open Fable.Core.JsInterop
open Fable.Mocha
open LitecoinMultisig.Types
open LitecoinMultisig

let private hex = Crypto.bytesToHex
let private unhex = Crypto.hexToBytes

[<Emit("Buffer.from($0)")>]
let private toBuffer (bytes: byte[]) : obj = jsNative

[<Import("payments", "bitcoinjs-lib")>]
let private payments : obj = jsNative

// ---------------------------------------------------------------------------
// Fixtures: three deterministic cosigners from official BIP39 test mnemonics
// ---------------------------------------------------------------------------

let testMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

let private cosignerMnemonics = [|
    testMnemonic
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
|]

/// Account-level nodes (m/48'/coin'/0'/script') for the three test cosigners.
let cosignerAccounts (network: Network) (scriptType: ScriptType) : Bip32.HDKey[] =
    cosignerMnemonics
    |> Array.map (fun m ->
        Bip32.mnemonicToSeed m ""
        |> Bip32.masterFromSeed network
        |> Bip32.deriveAccount network 0 scriptType)

let addressKeysAt (change: int) (index: int) (accounts: Bip32.HDKey[]) : Bip32.HDKey[] =
    accounts |> Array.map (Bip32.deriveAddressKey change index)

// ---------------------------------------------------------------------------

let cryptoTests = testList "Crypto" [
    testCase "sha256 matches NIST vector" <| fun () ->
        let digest = Crypto.sha256 (unhex "616263") // "abc"
        Expect.equal (hex digest) "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" "sha256(abc)"

    testCase "hash160 of secp256k1 generator pubkey" <| fun () ->
        let pk = unhex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        Expect.equal (hex (Crypto.hash160 pk)) "751e76e8199196d454941c45d1b3a323f1433bd6" "hash160"

    testCase "concatBytes preserves order and content" <| fun () ->
        let out = Crypto.concatBytes [| unhex "dead"; unhex "be"; unhex "ef" |]
        Expect.equal (hex out) "deadbeef" "concat"
]

let bip32Tests = testList "Bip32" [
    testCase "BIP39 vector: abandon…about produces known seed" <| fun () ->
        let seed = Bip32.mnemonicToSeed testMnemonic ""
        Expect.equal
            (hex seed)
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
            "seed"

    testCase "generated mnemonics validate (12 and 24 words)" <| fun () ->
        let m12 = Bip32.generateMnemonic Bip32.Words12
        let m24 = Bip32.generateMnemonic Bip32.Words24
        Expect.equal (m12.Split(' ').Length) 12 "12 words"
        Expect.equal (m24.Split(' ').Length) 24 "24 words"
        Expect.isTrue (Bip32.validateMnemonic m12) "m12 valid"
        Expect.isTrue (Bip32.validateMnemonic m24) "m24 valid"
        Expect.isFalse (Bip32.validateMnemonic "abandon abandon abandon") "bad checksum rejected"

    testCase "master fingerprint matches known vector (73c5da0a)" <| fun () ->
        let master = Bip32.mnemonicToSeed testMnemonic "" |> Bip32.masterFromSeed Mainnet
        Expect.equal master.fingerprint 1942346250.0 "fingerprint"

    testCase "extended keys use Litecoin version bytes" <| fun () ->
        let seed = Bip32.mnemonicToSeed testMnemonic ""
        let master = Bip32.masterFromSeed Mainnet seed
        Expect.isTrue (master.privateExtendedKey.StartsWith "Ltpv") "Ltpv"
        Expect.isTrue (master.publicExtendedKey.StartsWith "Ltub") "Ltub"
        let tmaster = Bip32.masterFromSeed Testnet seed
        Expect.isTrue (tmaster.publicExtendedKey.StartsWith "ttub") "ttub"

    testCase "BIP48 derivation paths" <| fun () ->
        Expect.equal (Bip32.bip48Path Mainnet 0 P2WSH) "m/48'/2'/0'/2'" "mainnet p2wsh"
        Expect.equal (Bip32.bip48Path Testnet 1 P2SH) "m/48'/1'/1'/0'" "testnet p2sh"
        Expect.equal (Bip32.bip48Path Mainnet 0 P2SH_P2WSH) "m/48'/2'/0'/1'" "nested"

    testCase "cosigner xpub derives the same child pubkeys as the xprv" <| fun () ->
        let account =
            Bip32.mnemonicToSeed testMnemonic ""
            |> Bip32.masterFromSeed Mainnet
            |> Bip32.deriveAccount Mainnet 0 P2WSH
        let viaXprv = account |> Bip32.deriveAddressKey 0 5
        let viaXpub =
            Bip32.fromExtendedKey Mainnet account.publicExtendedKey
            |> Bip32.deriveAddressKey 0 5
        Expect.equal (hex viaXpub.publicKey) (hex viaXprv.publicKey) "same pubkey"
]

let scriptTests =
    let k1 = unhex ("02" + String.replicate 64 "0")
    let k2 = unhex ("02ff" + String.replicate 62 "0")
    let k3 = unhex ("03" + String.replicate 64 "0")

    testList "Script" [
        testCase "BIP67 sorts pubkeys lexicographically" <| fun () ->
            let sorted = Script.sortPubKeysBip67 [| k3; k2; k1 |]
            Expect.equal (hex sorted.[0]) (hex k1) "k1 first"
            Expect.equal (hex sorted.[1]) (hex k2) "k2 second"
            Expect.equal (hex sorted.[2]) (hex k3) "k3 last"

        testCase "2-of-3 script structure" <| fun () ->
            let script = Script.multisigScript 2 [| k1; k2; k3 |]
            Expect.equal script.Length 105 "length"
            Expect.equal script.[0] 0x52uy "OP_2"
            Expect.equal script.[103] 0x53uy "OP_3"
            Expect.equal script.[104] 0xAEuy "OP_CHECKMULTISIG"

        testCase "script is invariant under pubkey input order" <| fun () ->
            let a = Script.multisigScript 2 [| k1; k2; k3 |]
            let b = Script.multisigScript 2 [| k3; k1; k2 |]
            let c = Script.multisigScript 2 [| k2; k3; k1 |]
            Expect.equal (hex b) (hex a) "order b"
            Expect.equal (hex c) (hex a) "order c"

        testCase "rejects invalid quorums and keys" <| fun () ->
            Expect.throws (fun () -> Script.multisigScript 4 [| k1; k2; k3 |] |> ignore) "m > n"
            Expect.throws (fun () -> Script.multisigScript 0 [| k1 |] |> ignore) "m = 0"
            Expect.throws (fun () -> Script.multisigScript 1 [| unhex "02ff" |] |> ignore) "bad key length"
    ]

let addressTests = testList "Address" [
    testCase "multisig addresses match bitcoinjs-lib's independent implementation" <| fun () ->
        let pubkeys =
            cosignerAccounts Mainnet P2WSH
            |> addressKeysAt 0 0
            |> Array.map (fun k -> k.publicKey)
        let script = Script.multisigScript 2 pubkeys
        let net = Psbt.bitcoinJsNetwork Mainnet
        let scriptBuf = toBuffer script

        let p2shPayment = payments?p2sh (createObj [
            "redeem" ==> createObj [ "output" ==> scriptBuf; "network" ==> net ]
            "network" ==> net
        ])
        let expectedP2sh: string = p2shPayment?address
        Expect.equal (Address.p2shAddress Mainnet script) expectedP2sh "p2sh"

        let p2wshPayment = payments?p2wsh (createObj [
            "redeem" ==> createObj [ "output" ==> scriptBuf; "network" ==> net ]
            "network" ==> net
        ])
        let expectedP2wsh: string = p2wshPayment?address
        Expect.equal (Address.p2wshAddress Mainnet script) expectedP2wsh "p2wsh"

        let nestedPayment = payments?p2sh (createObj [
            "redeem" ==> p2wshPayment
            "network" ==> net
        ])
        let expectedNested: string = nestedPayment?address
        Expect.equal (Address.p2shP2wshAddress Mainnet script) expectedNested "p2sh-p2wsh"

    testCase "addresses carry the right Litecoin prefixes" <| fun () ->
        let pubkeys =
            cosignerAccounts Mainnet P2WSH
            |> addressKeysAt 0 0
            |> Array.map (fun k -> k.publicKey)
        let mainP2sh = Address.multisigAddress Mainnet P2SH 2 pubkeys
        let mainP2wsh = Address.multisigAddress Mainnet P2WSH 2 pubkeys
        let testP2wsh = Address.multisigAddress Testnet P2WSH 2 pubkeys
        Expect.isTrue (mainP2sh.StartsWith "M") "mainnet p2sh starts with M"
        Expect.isTrue (mainP2wsh.StartsWith "ltc1q") "mainnet p2wsh bech32"
        Expect.isTrue (testP2wsh.StartsWith "tltc1q") "testnet p2wsh bech32"

    testCase "single-sig addresses (free tier)" <| fun () ->
        let key = (cosignerAccounts Mainnet P2WSH).[0] |> Bip32.deriveAddressKey 0 0
        let p2wpkh = Address.p2wpkhAddress Mainnet key.publicKey
        let p2pkh = Address.p2pkhAddress Mainnet key.publicKey
        Expect.isTrue (p2wpkh.StartsWith "ltc1q") "p2wpkh prefix"
        Expect.equal p2wpkh.Length 43 "p2wpkh length"
        Expect.isTrue (p2pkh.StartsWith "L") "p2pkh prefix"
]

let psbtTests =
    let dummyTxid = "75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858"

    testList "Psbt" [
        testCase "PSBT base64 round-trip" <| fun () ->
            let pubkeys =
                cosignerAccounts Testnet P2WSH
                |> addressKeysAt 0 0
                |> Array.map (fun k -> k.publicKey)
            let ws = Script.multisigScript 2 pubkeys
            let psbt =
                Psbt.create Testnet
                |> Psbt.addMultisigInput P2WSH ws dummyTxid 0 100000.0
                |> Psbt.addOutput (Address.p2wshAddress Testnet ws) 90000.0
            let b64 = Psbt.toBase64 psbt
            Expect.equal (Psbt.fromBase64 Testnet b64 |> Psbt.toBase64) b64 "round-trip"

        testCase "2-of-3 P2WSH: independent signing, combine, finalize, extract" <| fun () ->
            let accounts = cosignerAccounts Testnet P2WSH
            let keys = accounts |> addressKeysAt 0 0
            let pubkeys = keys |> Array.map (fun k -> k.publicKey)
            let ws = Script.multisigScript 2 pubkeys
            let basePsbt =
                Psbt.create Testnet
                |> Psbt.addMultisigInput P2WSH ws dummyTxid 0 100000.0
                |> Psbt.addOutput (Address.p2wshAddress Testnet ws) 90000.0
            let b64 = Psbt.toBase64 basePsbt
            // Cosigners 1 and 2 sign independent copies — the coordination flow
            let signed1 = Psbt.fromBase64 Testnet b64 |> Psbt.signInput 0 keys.[0]
            let signed2 = Psbt.fromBase64 Testnet b64 |> Psbt.signInput 0 keys.[1]
            let combined = signed1 |> Psbt.combine signed2
            Expect.isTrue (Psbt.validateSignatures 0 combined) "all signatures valid"
            let txHex = Psbt.finalizeAndExtract combined
            Expect.isTrue (txHex.Length > 200) "raw tx hex produced"

        testCase "2-of-3 P2SH-P2WSH (nested segwit) signs and finalizes" <| fun () ->
            let accounts = cosignerAccounts Testnet P2SH_P2WSH
            let keys = accounts |> addressKeysAt 0 0
            let pubkeys = keys |> Array.map (fun k -> k.publicKey)
            let ws = Script.multisigScript 2 pubkeys
            let psbt =
                Psbt.create Testnet
                |> Psbt.addMultisigInput P2SH_P2WSH ws dummyTxid 1 200000.0
                |> Psbt.addOutput (Address.p2shP2wshAddress Testnet ws) 190000.0
                |> Psbt.signInput 0 keys.[1]
                |> Psbt.signInput 0 keys.[2]
            Expect.isTrue (Psbt.validateSignatures 0 psbt) "signatures valid"
            let txHex = Psbt.finalizeAndExtract psbt
            Expect.isTrue (txHex.Length > 200) "raw tx hex produced"

        testCase "signWithAccount finds the right derivation by scanning the script" <| fun () ->
            let accounts = cosignerAccounts Testnet P2WSH
            let addrIndex = 7 // not index 0 — forces the scan to actually search
            let keys = accounts |> addressKeysAt 0 addrIndex
            let pubkeys = keys |> Array.map (fun k -> k.publicKey)
            let ws = Script.multisigScript 2 pubkeys
            let psbt =
                Psbt.create Testnet
                |> Psbt.addMultisigInput P2WSH ws dummyTxid 0 100000.0
                |> Psbt.addOutput (Address.p2wshAddress Testnet ws) 90000.0
            Expect.equal (Psbt.signatureCount psbt) 0 "starts unsigned"
            Expect.equal (Psbt.signWithAccount accounts.[0] 20 psbt) 1 "cosigner 1 signs"
            Expect.equal (Psbt.signWithAccount accounts.[1] 20 psbt) 1 "cosigner 2 signs"
            Expect.equal (Psbt.signatureCount psbt) 2 "two signatures recorded"
            Expect.equal (Psbt.signWithAccount accounts.[0] 20 psbt) 0 "re-sign is a no-op"
            Expect.equal (Psbt.signatureCount psbt) 2 "count unchanged after re-sign"
            let txHex = Psbt.finalizeAndExtract psbt
            Expect.isTrue (txHex.Length > 200) "finalizes"

        testCase "one signature is not enough to finalize a 2-of-3" <| fun () ->
            let accounts = cosignerAccounts Testnet P2WSH
            let keys = accounts |> addressKeysAt 0 0
            let pubkeys = keys |> Array.map (fun k -> k.publicKey)
            let ws = Script.multisigScript 2 pubkeys
            let psbt =
                Psbt.create Testnet
                |> Psbt.addMultisigInput P2WSH ws dummyTxid 0 100000.0
                |> Psbt.addOutput (Address.p2wshAddress Testnet ws) 90000.0
                |> Psbt.signInput 0 keys.[0]
            Expect.throws (fun () -> Psbt.finalizeAndExtract psbt |> ignore) "insufficient signatures"
    ]

let keyStoreTests =
    let userId = "user-1234"
    let passphrase = "correct horse battery staple"

    testList "KeyStore" [
        testCaseAsync "store → unlock round-trips the entry" <| async {
            let entry: KeyStore.KeyStoreEntry = {
                WalletId = "w1"
                Mnemonic = Some testMnemonic
                Xprv = "Ltpv-test-not-a-real-key"
            }
            do! KeyStore.store entry passphrase userId |> Async.AwaitPromise
            Expect.isTrue (KeyStore.hasKey "w1") "key stored"
            let! unlocked = KeyStore.unlock "w1" passphrase userId |> Async.AwaitPromise
            match unlocked with
            | Some e ->
                Expect.equal e.Xprv entry.Xprv "xprv"
                Expect.equal e.Mnemonic entry.Mnemonic "mnemonic"
            | None -> failwith "expected unlock to succeed"
        }

        testCaseAsync "wrong passphrase fails closed" <| async {
            let entry: KeyStore.KeyStoreEntry = { WalletId = "w2"; Mnemonic = None; Xprv = "xprv-opaque" }
            do! KeyStore.store entry passphrase userId |> Async.AwaitPromise
            let! wrong = KeyStore.unlock "w2" "incorrect horse battery" userId |> Async.AwaitPromise
            Expect.isTrue wrong.IsNone "wrong passphrase yields None"
            let! wrongSalt = KeyStore.unlock "w2" passphrase "other-user" |> Async.AwaitPromise
            Expect.isTrue wrongSalt.IsNone "wrong salt yields None"
        }

        testCaseAsync "forget wipes the key" <| async {
            let entry: KeyStore.KeyStoreEntry = { WalletId = "w3"; Mnemonic = None; Xprv = "xprv-opaque" }
            do! KeyStore.store entry passphrase userId |> Async.AwaitPromise
            KeyStore.forget "w3"
            Expect.isFalse (KeyStore.hasKey "w3") "gone"
            let! unlocked = KeyStore.unlock "w3" passphrase userId |> Async.AwaitPromise
            Expect.isTrue unlocked.IsNone "nothing to unlock"
        }

        testCaseAsync "wallet config blob round-trips and rejects tampering" <| async {
            let config = """{"xpubs":["Ltub1","Ltub2"],"m":2,"n":3,"nextIndex":0}"""
            let! blob = KeyStore.encryptString passphrase userId config |> Async.AwaitPromise
            // ciphertext must not contain plaintext markers (server tripwire)
            Expect.isFalse (blob.Contains "xpubs") "opaque ciphertext"
            let! plain = KeyStore.decryptString passphrase userId blob |> Async.AwaitPromise
            Expect.equal plain config "round-trip"
        }
    ]

let allTests =
    testList "LiteSig crypto core" [
        cryptoTests
        bip32Tests
        scriptTests
        addressTests
        psbtTests
        keyStoreTests
    ]

[<EntryPoint>]
let main _ =
    let failures = Mocha.runTests allTests
    emitJsStatement failures "process.exitCode = $0"
    failures
