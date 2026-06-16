namespace LitecoinMultisig

module Types =

    type Network =
        | Mainnet
        | Testnet

    /// Multisig script encodings supported by the wallet.
    type ScriptType =
        | P2SH
        | P2WSH
        | P2SH_P2WSH

    type NetworkParams = {
        Bech32Hrp  : string
        PubKeyHash : byte
        ScriptHash : byte
        WifPrefix  : byte
        CoinType   : uint32
    }

    // Modern Litecoin prefixes: P2SH is 0x32 ('M…') on mainnet, 0x3A on testnet.
    // The legacy 0x05/0xC4 prefixes are deprecated — they collide with Bitcoin
    // '3…' addresses, which historically caused cross-chain fund loss.
    let mainnet = { Bech32Hrp = "ltc";  PubKeyHash = 0x30uy; ScriptHash = 0x32uy; WifPrefix = 0xB0uy; CoinType = 2u }
    let testnet = { Bech32Hrp = "tltc"; PubKeyHash = 0x6Fuy; ScriptHash = 0x3Auy; WifPrefix = 0xEFuy; CoinType = 1u }

    let networkParams =
        function
        | Mainnet -> mainnet
        | Testnet -> testnet

    let networkToString =
        function
        | Mainnet -> "mainnet"
        | Testnet -> "testnet"

    let scriptTypeToString =
        function
        | P2SH -> "p2sh"
        | P2WSH -> "p2wsh"
        | P2SH_P2WSH -> "p2sh-p2wsh"
