# Certificate Store CLI

This basic utility can be used to create internal certificates via OpenSSL.

The utility allows basic storage of the created certificates for persistence.
It is advisable that the certificate store file `certstore.db` be protected with filesystem permissions, as the file can be opened by any Sqlite client.

The certificates use SHA256 and 2048 bit depth, as this is a purely academic utility, not intended for use in production scenarios.

## Dependencies

- Sqlite (system.data.sqlite)
- dotnet sdk 8

## Build / Run

```sh
dotnet build
cd certstore.cli
dotnet run
```

## Output example 
(after the initial rootca intermediateca and server certificates are created)

```sh
Certificate Store
Usage:
  export-public-key <certId>
  export-private-key <certId>
  export-public-key-chain <certId>
  list-certificates
  list-expired-certificates
  get-certificate-thumbprint <certId>
  add-certificate-file <filePath>
  remove-certificate <certId>
```