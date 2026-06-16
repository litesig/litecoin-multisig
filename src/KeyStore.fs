module LitecoinMultisig.KeyStore

open Fable.Core
open Fable.Core.JsInterop

/// AES-256-GCM helpers (PBKDF2-derived key). Also used to encrypt the wallet
/// config blob before it is synced to the server.
[<Import("encryptString", "./webcrypto.js")>]
let encryptString (passphrase: string) (salt: string) (plaintext: string) : JS.Promise<string> = jsNative

[<Import("decryptString", "./webcrypto.js")>]
let decryptString (passphrase: string) (salt: string) (payloadB64: string) : JS.Promise<string> = jsNative

type KeyStoreEntry = {
    WalletId: string
    Mnemonic: string option // only if the user opted to store it
    Xprv: string
}

// localStorage in the browser; an in-memory shim under Node (tests).
let private storage: obj =
    emitJsExpr
        ()
        "typeof localStorage !== 'undefined' ? localStorage : (() => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) }; })()"

let private keyFor (walletId: string) = "ltc_ks_" + walletId

/// Encrypt and persist key material. Salt is the userId (per spec); the
/// passphrase itself is never stored anywhere.
let store (entry: KeyStoreEntry) (passphrase: string) (userId: string) : JS.Promise<unit> =
    promise {
        let payload =
            JS.JSON.stringify (
                createObj [
                    "mnemonic" ==> (match entry.Mnemonic with Some m -> box m | None -> null)
                    "xprv" ==> entry.Xprv
                ]
            )
        let! encrypted = encryptString passphrase userId payload
        storage?setItem (keyFor entry.WalletId, encrypted)
    }

/// Decrypt the stored entry. Returns None when nothing is stored or the
/// passphrase is wrong (GCM authentication failure).
let unlock (walletId: string) (passphrase: string) (userId: string) : JS.Promise<KeyStoreEntry option> =
    promise {
        let stored: string = storage?getItem (keyFor walletId)
        if isNullOrUndefined stored then
            return None
        else
            try
                let! plain = decryptString passphrase userId stored
                let parsed = JS.JSON.parse plain
                let mnemonic: string = parsed?mnemonic
                return
                    Some {
                        WalletId = walletId
                        Mnemonic = if isNullOrUndefined mnemonic then None else Some mnemonic
                        Xprv = parsed?xprv
                    }
            with _ ->
                return None
    }

let hasKey (walletId: string) : bool =
    let stored: string = storage?getItem (keyFor walletId)
    not (isNullOrUndefined stored)

/// Wipe key material for a wallet from this device.
let forget (walletId: string) : unit = storage?removeItem (keyFor walletId)
