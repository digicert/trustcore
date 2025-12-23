Seal Operation:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/tap_nanoroot_example --config <nanoroot_smp config file> --infile <input file to seal> --outfile <output sealed file> --seal --passphrase <password>
```

Unseal Operation:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/tap_nanoroot_example --config <nanoroot smp config file> --infile <sealed input file> --outfile <output unsealed file> --unseal --passphrase <password>
```

Sign Operation:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/tap_nanoroot_example --config <nanoroot smp config file> --infile <input file to sign> --outfile <file to store signature> --pubKey <file to store public key> --keyId <specify type of key to generate> --signBuffer --hashType <hashType>
```

Verify Operation:
```bash
export LD_LIBRARY_PATH=lib/:$LD_LIBRARY_PATH
./samples/bin/tap_nanoroot_example --config <nanoroot smp config file> --infile <input file to verify > --outfile <input signature file> --pubKey <input public key file> --keyId <specify type of key to use to verify> --verify --hashType <hashType>
```
