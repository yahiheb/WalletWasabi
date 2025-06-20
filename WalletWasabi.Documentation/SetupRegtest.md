# Bitcoin Setup (RegTest)

## What is RegTest?

RegTest is a local network in which users can generate blocks and coins for testing. Running Indexer and Coordinator in RegTest allows you to emulate network events and observe how the Wasabi react on that. You don't need to download the blockchain.

## Bitcoin Core Setup

1. Install Bitcoin Core from the [Official Website](https://bitcoincore.org/en/download/) or [GitHub](https://github.com/bitcoin/bitcoin/releases/) on your computer. Verify the PGP signatures. Check the security advisories [here](https://bitcoincore.org/en/security-advisories/).
2. Start Bitcoin Core with: `bitcoin-qt.exe -regtest` then select Bitcoin data directory or leave it as the default. If you use the `-datadir` parameter, make sure the directory exists.

    `-datadir` using example:

    Windows:
    ```
    "C:\Program Files\Bitcoin\bitcoin-qt.exe" -regtest -blockfilterindex -txindex -datadir=C:\Bitcoin
    ```
    macOS:
    ```
    "/Applications/Bitcoin-Qt.app/Contents/MacOS/Bitcoin-Qt" -regtest -blockfilterindex -txindex -datadir=$HOME/Library/Application Support/Bitcoin"
    ```
    Linux:
    ```
     ~/bitcoin-[version number]/bin/bitcoin-qt -regtest -blockfilterindex -txindex -datadir=$HOME/.bitcoin/
    ```

4. Go to Bitcoin data directory.

    There may be differences if you used the `-datadir` parameter before.

    Defaults:

    Windows:
    ```
    %APPDATA%\Bitcoin\
    ```
    macOS:
    ```
    $HOME/Library/Application Support/Bitcoin/
    ```
    Linux:
    ```
    $HOME/.bitcoin/
    ```
4. Edit / Create a **bitcoin.conf** file and add these lines:
    ```C#
    regtest.server = 1
    regtest.listen = 1
    regtest.txindex = 1
    regtest.whitebind = 127.0.0.1:18444
    regtest.rpchost = 127.0.0.1
    regtest.rpcport = 18443
    regtest.rpcuser = rpcuser
    regtest.rpcpassword = rpcpassword
    regtest.disablewallet = 0
    regtest.softwareexpiry = 0
    regtest.listenonion = 0
    regtest.blockfilterindex = 1
    ```
5. Save it.
6. Close Bitcoin Core to confirm changes and open it again with: `bitcoin-qt.exe -regtest`.
7. Do not worry about "Syncing Headers" just press the Hide button. Because you run on Regtest, no Mainnet blocks will be downloaded.
8. Go to menu *File / Create* and create a wallet with the name you prefer. Use the default options.
9. Go to menu *Window / Console*.
10. Generate a new address with:
`getnewaddress`
11. Generate the first 101 blocks with:
`generatetoaddress 101 <replace_new_address_here>`
12. Now you have your own Bitcoin blockchain. You can create transactions with the Send button and confirm with creating a new block:
`generatetoaddress 1 <replace_new_address_here>`

You can force rebuilding the txindex with the `-reindex` command line argument. Bitcoin Core needs to be running during the next steps.

# Wasabi Setup

Here you will have to build from source, follow [these instructions here](https://github.com/WalletWasabi/WalletWasabi#build-from-source-code).

## Indexer Setup

1. Go to `WalletWasabi\WalletWasabi.Backend` folder.
2. Open the command line and enter:
`dotnet run`
3. You will get some errors, but the data directory will be created.
4. Stop the application if it is still running with CTRL-C.
5. Go to the Indexer folder:
    ```
    Windows: "C:\Users\{your username}\AppData\Roaming\WalletWasabi\Backend"
    macOS: "/Users/{your username}/.walletwasabi/backend"
    Linux: "/home/{your username}/.walletwasabi/backend"
    ```
6. Edit these lines in `Config.json`:
    ```
      "Network": "RegTest",
      "BitcoinRpcConnectionString": "rpcuser:rpcpassword",
    ```
7. Go to WalletWasabi.Backend folder.
8. Open the command line and enter:
`dotnet run`
9. Wasabi.Backend is now running in RegTest network.

## Coordinator Setup

1. Go to `WalletWasabi\WalletWasabi.Coordinator` folder.
2. Open the command line and enter:
`dotnet run`
3. You will get some errors, but the data directory will be created.
4. Stop the application if it is still running with CTRL-C.
5. Go to the Coordinator folder:
    ```
    Windows: "C:\Users\{your username}\AppData\Roaming\WalletWasabi\Coordinator"
    macOS: "/Users/{your username}/.walletwasabi/coordinator"
    Linux: "/home/{your username}/.walletwasabi/coordinator"
    ```
6. Edit these lines in `Config.json`:
    ```
    "Network": "RegTest",
    "BitcoinRpcConnectionString": "rpcuser:rpcpassword",
    "StandardInputRegistrationTimeout": "0d 0h 2m 0s",
    "MinInputCountByRoundMultiplier": 0.02,
    ```
7. Go to WalletWasabi.Coordinator folder.
8. Open the command line and enter:
`dotnet run`
9. Wasabi.Coordinator is now running in RegTest network

## Client Setup

1. Go to `WalletWasabi\WalletWasabi.Fluent.Desktop` folder.
2. Open the command line and run the Wasabi Client with:
`dotnet run`
3. Go to Settings/Bitcoin and set the network to RegTest
4. Close Wasabi and restart it with:
`dotnet run`
5. Generate a wallet in Wasabi named: R1.
6. Generate a receive address in Wasabi, now go to Bitcoin Core to the Send tab.
7. Send 1 BTC to that address.
8. Generate a wallet in Wasabi named: R2.
9. Generate a receive address in Wasabi, now go to Bitcoin Core to the Send tab.
10. Send 1 BTC to that address.
11. Now let the coinjoin happen automatically in both wallets.
12. If you see `Waiting for confirmed funds` in the music box you can generate a block in Bitcoin Core to continue coinjoining:
`generatetoaddress 1 <replace_new_address_here>`
