# PQC Verification Tools


## Current Pipeline
```
Firmware (image.bin)
        ↓
Signature Generation
(generate_test_data)
        ↓
Signature + Public Key
        ↓
Verification
(pqc_verify)
        ↓
VALID / INVALID
```

## Building and Running

1. Ubuntu installation
```
sudo apt update
sudo apt install gcc cmake ninja-build libssl-dev
```

2. Install Liboqs
```
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake -GNinja ..
ninja
sudo ninja install
sudo ldconfig
```

3. Build Project
```
...src/pqc make
```

4. Generate Test Keys and Signature
```
make gen
./generate_test_data
```

this creates
```
tests/pubkey.bin
tests/seckey.bin
tests/image.sig
```

5. Run Verification 

```
./pqc_verify ../../tests/image.bin ../../tests/image.sig ../../tests/pubkey.bin
```

Expected output

```
Algorithm: ML-DSA-65
Image: ../../tests/image.bin (22 bytes)
Signature: ../../tests/image.sig (3309 bytes)
Public key: ../../tests/pubkey.bin (1952 bytes)
Verification: VALID
Verification time: XXXX us
```