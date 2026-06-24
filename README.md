# Technical Report: SAKE library Reverse Engineering


## Sake Cryptographic Library (`libandroid-sake-lib_v210.so`)

**Date:** June 15, 2026

**Status:** 100% Analysis Coverage (Zero Unnamed Functions Remaining)

---


## 0. Final Binary Statistics

| Metric | Value |
|:---|:---|
| Total functions | 337 |
| FUN_* remaining | **0** |
| Functions renamed | ~120+ |
| EOL comments added | ~80+ |
| Ghidra structs created | 7 |
| Ghidra enums created | 7 |
| Struct fields with enums | 9 |
| Function prototypes with enums | 8 |
| Labels created | 150+ |
| Sections documented | 24 |
| SAKE-specific functions | ~150 |
| ARM/NDK infrastructure | ~187 |



## 1. Executive Summary & Binary Metadata

This document serves as the comprehensive, authoritative reverse engineering and reimplementation guide for the `libandroid-sake-lib_v210.so` binary. This shared library implements **SAKE**, a proprietary protocol used to secure Bluetooth Low Energy (BTLE) GATT messaging between an Android client and Medtronic Minimed medical devices.

### 1.1. Core Metadata
*   **Filename:** `libandroid-sake-lib_v210.so`
*   **Format:** Executable and Linking Format (ELF) 32-bit Shared Object
*   **Target Architecture:** ARM (32-bit, Little-Endian, v8-A/v8-R profile)
*   **Default Base Address:** `0x00010000`
*   **Compiler Toolchain:** GCC / Android NDK (Clang/LLVM with GCC compatibility wrappers)
*   **Security Mechanisms:** 
    *   Stack Smashing Protector (Canary): Enabled (`__stack_chk_guard` / `__stack_chk_fail`)
    *   Position Independent Code (PIC/PIE): Enabled
    *   Symbol Stripping: Non-stripped (symbol table and dynamic linking symbols are fully intact)

---

## 2. Memory Map & Section Structure

The binary layout is structured into standard ELF segments. The virtual addresses (relative to base `0x00010000`) are detailed below:

| Section Name | Start Address | End Address | Access Flags | Description |
| :--- | :--- | :--- | :--- | :--- |
| `segment_1.1` | `0x00010000` | `0x00010133` | `R--` | ELF Header & Program Headers |
| `.note.android.ident`| `0x00010134` | `0x000101cb` | `R--` | NDK target API levels |
| `.note.gnu.build-id`| `0x000101cc` | `0x000101ef` | `R--` | GNU Build Identifier Hash |
| `.dynsym` | `0x000101f0` | `0x00010c1f` | `R--` | Dynamic Linker Symbols (163 entries) |
| `.dynstr` | `0x00010c20` | `0x00013335` | `R--` | Dynamic String Constants |
| `.hash` | `0x00013338` | `0x000137d7` | `R--` | Symbol Hash Table for lookups |
| `.gnu.version` | `0x000137d8` | `0x0001391d` | `R--` | Symbol Version Requirements |
| `.rel.dyn` | `0x0001397c` | `0x00013c33` | `R--` | Non-PLT dynamic relocations |
| `.rel.plt` | `0x00013c34` | `0x00013d03` | `R--` | PLT-specific dynamic relocations |
| `.plt` | `0x00013d04` | `0x00013e4f` | `R-X` | Procedure Linkage Table (stub entries) |
| **`.text`** | `0x00013e50` | `0x00018c23` | `R-X` | **Executable Code Section (Instructions)** |
| `.ARM.exidx` | `0x00018c24` | `0x0001940b` | `R--` | Exception handling index table |
| `.rodata` | `0x00019a24` | `0x0001cb67` | `R--` | Read-only Constants, S-Boxes, Strings |
| `.data.rel.ro` | `0x0001dc50` | `0x0001de67` | `RW-` | Relocations made read-only after load |
| `.dynamic` | `0x0001de68` | `0x0001df67` | `RW-` | Dynamic linking structural descriptors |
| `.got` | `0x0001df70` | `0x0001dfff` | `RW-` | Global Offset Table |
| `.data` | `0x0001e000` | `0x0001e007` | `RW-` | Initialized Mutable Global Variables |
| `.bss` | `0x0001e008` | `0x0001e027` | `RW-` | Uninitialized Mutable Global Variables |

---

## 3. Cryptographic Implementation Details

The library implements standard symmetric cryptosystems, heavily optimized using traditional table-lookup architectures to avoid runtime overhead in resource-constrained environments.

### 3.1. AES-128 Symmetric Engine
The core symmetric cipher is standard AES-128. However, instead of executing shifts, substitutions, and mix-column transformations on the fly, the compiler has flattened the cipher rounds into **AES T-Tables** mapping to memory page `0x0001a540`.

#### 3.1.1. S-Box Table (`AES_SBOX`)
Located at address **`0x0001a568`**, this contains the standard Rijndael substitution box (256 bytes):
```hex
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
... [standard AES S-box layout]
```

#### 3.1.2. Round Constants (`AES_RCON`)
Located at address **`0x0001a540`**, this represents the Rijndael round constant array used during the key schedule expansion:
```hex
01 00 00 00  02 00 00 00  04 00 00 00  08 00 00 00
10 00 00 00  20 00 00 00  40 00 00 00  80 00 00 00
1b 00 00 00  36 00 00 00
```

### 3.2. Secure Messaging Encryption: AES-128-CTR
Data payloads are encrypted using **AES-128-CTR (Counter Mode)**.
*   **Counter Properties:** The counter is a full 16-byte (128-bit) big-endian block.
*   **Implementation (`SakeCrypto_AES_CTR_Transform` at `0x00016be6`):**
    *   Checks the block offset index. If it hits a block boundary (modulo 16), it invokes the underlying raw block cipher `SakeCrypto_AES_EncryptBlock` (`0x00016590`) on the counter block to yield a fresh 16-byte keystream.
    *   Performs a big-endian multi-byte increment on the counter structure:
        ```c
        // Inlined counter addition loop
        int i = 15;
        do {
            char val = counter_block[i];
            counter_block[i] = val + 1;
            i--;
        } while (val == -1); // Carry propagation if byte overflowed (0xFF -> 0x00)
        ```
    *   Applies the keystream to the data using parallel bitwise XOR operations.

### 3.3. Message Authentication: AES-CMAC
For message integrity, the library implements a variant of **AES-CMAC** (NIST SP 800-38B).

#### 3.3.1. Galois Field Multiplication (`SakeCrypto_GF_Double` at `0x0001749c`)
To derive the subkeys $K_1$ and $K_2$ used to process complete and incomplete blocks, the library implements shift-and-XOR finite-field doubling in $GF(2^8)$.
*   **128-bit Block Mode (Polynomial `0x87`):**
    If the size parameter is `0x10` (16 bytes), the shift overflow is XORed with standard AES polynomial parameter:
    $$\text{Irreducible Polynomial} = x^7 + x^2 + x + 1 \implies 0x87$$
*   **64-bit Block Mode (Polynomial `0x1b`):**
    If the size is `8` bytes, the fallback reduction uses the 64-bit polynomial:
    $$\text{Polynomial} = x^4 + x^3 + x + 1 \implies 0x1b$$
*   **Inline C Implementation:**
    ```c
    byte carry = 0;
    for (int i = size - 1; i >= 0; i--) {
        byte next_carry = input[i] >> 7;
        output[i] = (input[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry) {
        output[size - 1] ^= polynomial; // 0x87 or 0x1b depending on block size
    }
    ```

#### 3.3.2. MAC Appending and Truncation
*   The raw AES-CMAC operation generates a full 16-byte authentication tag.
*   **Truncation:** The high-level secure message wrapper (`SakeCrypto_EncryptSignMessage` at `0x00015028`) truncates the 128-bit MAC down to a **16-bit (2-byte) tag**.
*   This 2-byte tag is appended to the tail end of the encrypted payload before BLE transmission. The receiver extracts this tag, recalculates the CMAC over the payload and sequence context, and performs a 16-bit comparison.

---

## 4. Reconstructed Struct Layouts & Definitions

To reconstruct the protocol or interface with the library, the following memory layouts must be compiled exactly.

### 4.1. Core Handshake State Structure (`SAKE_CLIENT_S` / `SAKE_SERVER_S`)
This structure tracks the overall cryptographic state of a session. It is approximately `0x1A0` bytes in size.

```c
typedef struct {
    uint32_t currentState;                // +0x00: Current state machine index (1-8)
    uint32_t lowSequenceNumber;           // +0x04: Incremented per message (Counter Low)
    uint32_t highSequenceNumber;          // +0x08: Counter High for 64-bit sequence tracking
    uint8_t  localChallenge[20];          // +0x0C: Locally generated 20-byte random challenge (Rc)
    uint8_t  remoteChallenge[20];         // +0x20: Received 20-byte remote challenge (Rs)
    void*    cryptoVtablePtr;             // +0x34: Points to the cryptosystem descriptor vtable (0x0001de04)
    uint32_t dataLength;                  // +0x38: Working buffer length
    uint8_t  sessionKey_CTR[16];          // +0x3C: Inferred Derived AES-CTR Session Key
    uint8_t  sessionKey_CMAC[16];         // +0x4C: Inferred Derived AES-CMAC Session Key
    uint32_t handshakeStatus;             // +0x74: Error/Status flags (2 = Error, 8 = Success)
} SAKE_CLIENT_S;
```

### 4.2. Key Database Structure (`SAKE_KEY_DATABASE_S`)
The library manages an internal file-backed database representing trusted keys.
*   **Database Header:** `*dbPtr` contains a base descriptor. `*dbPtr + 5` tracks the active `entryCount`.
*   **Entries:** Array of packed **81-byte entries** (`0x51` bytes per entry).

```c
#pragma pack(push, 1)
typedef struct {
    uint8_t  deviceType;                  // +0x00: Device identifier type (compares via strcmp/char)
    uint8_t  reserved[6];                 // +0x01: Padding and metadata
    uint8_t  key1[16];                    // +0x07: Cryptographic Key 1
    uint8_t  key2[16];                    // +0x17: Handshake Root/Verification Key (K_root)
    uint8_t  key3[16];                    // +0x27: Cryptographic Key 3
    uint8_t  key4[16];                    // +0x37: Cryptographic Key 4
    uint8_t  key5[16];                    // +0x47: Cryptographic Key 5
    uint8_t  reserved_tail[10];           // +0x57: Trailing entry padding
} SAKE_KEY_ENTRY;
#pragma pack(pop)
```

---

## 5. Reverse Engineered Function Catalog

The following is an exhaustive directory of reversed functions compiled during this session.

### 5.1. `SakeClient_HandshakeHandler`
*   **Address:** `0x000145b6`
*   **Signature:** `uint32_t SakeClient_HandshakeHandler(void* clientContext, void* clientBufferPtr, int* stateMachineStatePtr)`
*   **Description:** The master driver for the client handshake. It evaluates `*stateMachineStatePtr` and routes execution to specific state processing functions:
    *   **State 1 (Init/Reset):** Calls `HandleHandshakeStateInitOrError` (`0x00014992`).
    *   **State 2 (Exchange):** Calls `SakeClient_ProcessHandshakeStep2` (`0x000149c4`) to process and validate incoming remote challenges.
    *   **State 3 (Derivation):** Calls `SakeClient_ProcessHandshakeStep3` (`0x00014a42`) to run the key derivation algorithm.
    *   **State 4 (Authentication):** Calls `SakeCrypto_PerformEncryptDecrypt` (`0x00014f44`) to cryptographically sign/verify the validation payload.

### 5.2. `SakeClient_GenerateChallenge`
*   **Address:** `0x00015c3c`
*   **Signature:** `uint32_t SakeClient_GenerateChallenge(int param_1)`
*   **Description:** Called during handshake setup. Sets the challenge length to `0x14` (20 bytes) and invokes `SakeUtil_ReadRandomBytes` to populate the structure buffer with strong random material from `/dev/urandom`.

### 5.3. `SakeUtil_ReadRandomBytes`
*   **Address:** `0x00017518`
*   **Signature:** `uint32_t SakeUtil_ReadRandomBytes(uint32_t byteCount, int destinationBuffer)`
*   **Description:** Opens `/dev/urandom` in read-only mode (`"r"`) using standard libc `fopen`. Iterates `byteCount` times, calling `fgetc` to read raw hardware-derived entropy, and copies the stream to `destinationBuffer`. Closes the stream on completion or read failure.

### 5.4. `SakeKeyDB_FindEntryByType`
*   **Address:** `0x000151fa`
*   **Signature:** `int* SakeKeyDB_FindEntryByType(int* dbPtr, char deviceType)`
*   **Description:** Iterates through the loaded database structure. It starts at index `0` and steps through memory by multiplying the current index by entry size `0x51` (81 bytes). Compares the first byte of each entry with `deviceType`. Returns a direct pointer to the matched entry or `NULL` if not found.

### 5.5. `SakeCrypto_AES_ProcessBlock`
*   **Address:** `0x00016244`
*   **Signature:** `uint64_t SakeCrypto_AES_ProcessBlock(int* cryptoState, uint* inputData, uint modeFlag)`
*   **Description:** The core block cipher execution engine. Decides round limits and algorithm behavior based on block flags (`0x80` -> 128-bit ECB/CTR; `0x100` -> 256-bit CBC). Performs high-performance round transformations via T-tables.

### 5.6. `SakeCrypto_AES_CTR_Transform`
*   **Address:** `0x00016be6`
*   **Signature:** `uint32_t SakeCrypto_AES_CTR_Transform(void* cipherContext, int bufferPtr, uint* stateOutput, int inputData, int outputBuffer, byte* inputKeyOrState, byte* outputByte)`
*   **Description:** Applies AES-CTR encryption/decryption. Generates keystream blocks by calling the block cipher on the 16-byte counter block, updates the big-endian counter by 1, and XORs the data blocks.

### 5.7. `SakeClient_InitChallengeAndSetState`
*   **Address:** `0x00014a22`
*   **Signature:** `uint32_t SakeClient_InitChallengeAndSetState(int clientCtx, int bufferPtr)`
*   **Description:** Generates 20-byte challenge via `/dev/urandom`, sets handshake state to `0x0B` (challenge ready), clears buffer at `+0x20`. Returns 8 on success, 7 on failure.

### 5.8. `SakeClient_GenerateAndEncryptSessionProof`
*   **Address:** `0x00014ad0`
*   **Signature:** `void SakeClient_GenerateAndEncryptSessionProof(int clientCtx, int bufferPtr)`
*   **Description:** Reads 16 random bytes, prepares cipher state via `SakeCrypto_InitCipherState`, encrypts via `SakeCrypto_EncryptSignAndIncrementSequence`. Error states: `0x0D` (random fail), `0x0F` (encrypt fail).

### 5.9. `SakeClient_ProcessHandshakeStep4_FinalizeAndValidate`
*   **Address:** `0x00014b58`
*   **Signature:** `void SakeClient_ProcessHandshakeStep4_FinalizeAndValidate(int clientCtx, int serverBuffer, int outputPtr)`
*   **Description:** State 4 finalizer. Looks up key DB entry, verifies client handshake proof, encrypts/decrypts server permit, validates encrypted response, generates 1 random byte, copies 48-byte result to `+0x40`. Error states: `0x0C`-`0x13`.

### 5.10. `SakeCrypto_EncryptSignAndIncrementSequence`
*   **Address:** `0x00014e3c`
*   **Signature:** `void SakeCrypto_EncryptSignAndIncrementSequence(int* cipherState, int plaintext, int output, int extra)`
*   **Description:** Core encrypt+sign wrapper. Calls `sakeCrypto_LowLevelPrimitive` then `SakeCrypto_EncryptSignMessage`. On success, **increments 64-bit sequence counter** at `param_1[2]/param_1[3]`. Called from **6 locations**.

### 5.11. `SakeClient_GenerateChallengeAndPackOutput`
*   **Address:** `0x00015a78`
*   **Signature:** `bool SakeClient_GenerateChallengeAndPackOutput(byte deviceType, uint* out1, uint* out2, uint* challengeBuf)`
*   **Description:** Generates 20-byte challenge, copies 8 bytes to output buffer, sets device type byte at `+0x10` of output.

### 5.12. `SakeClient_VerifyHandshakeProof`
*   **Address:** `0x00014d94`
*   **Signature:** `void SakeClient_VerifyHandshakeProof(uint* localChallenge, uint* remoteChallenge, int keyMaterial, int output)`
*   **Description:** Copies local and remote challenges (8 bytes each) into stack buffer, calls `SakeCrypto_VerifyHandshakeStep1` to validate proof.

### 5.13. `SakeClient_VerifyHandshakeMAC`
*   **Address:** `0x00015e3c`
*   **Signature:** `void SakeClient_VerifyHandshakeMAC(uint* challengeData, int keyBuf, int macBuf, int extra, uint* out1, uint* out2)`
*   **Description:** Verifies handshake MAC. Checks challenge length == 20 bytes, extracts keys from structure, calls `SakeCrypto_HandshakeWrapper`, then `SakeCrypto_Memcmp` to compare computed vs expected MAC.

### 5.14. `SakeKeyDB_LookupEntryByType`
*   **Address:** `0x00015360`
*   **Signature:** `int SakeKeyDB_LookupEntryByType(int* dbPtr, int deviceType)`
*   **Description:** Validates device type via `SakeKeyDB_IsValidDeviceType`, searches key database via `SakeKeyDB_FindEntryByType`, returns `entry + 1` or 0 if not found.

### 5.15. `SakeClient_DeriveSessionKeysAndFillRandom`
*   **Address:** `0x00015b6c`
*   **Signature:** `void SakeClient_DeriveSessionKeysAndFillRandom()`
*   **Description:** Step 3 driver. Calls `SakeCrypto_HandshakeVerifyAndDeriveKeys`, then `SakeUtil_FillChallengeWithRandom` to pad challenge to 20 bytes.

### 5.16. `SakeClient_PerformKeyConfirmation`
*   **Address:** `0x00015cb8`
*   **Signature:** `void SakeClient_PerformKeyConfirmation()`
*   **Description:** Key confirmation loop. Generates random iteration count (1-4), loops that many times: reads 16 random bytes + 32 random bytes, calls `SakeCrypto_VerifyMessage` to confirm key material.

### 5.17. `SakeCrypto_HandshakeVerifyAndDeriveKeys`
*   **Address:** `0x00015ae0`
*   **Signature:** `void SakeCrypto_HandshakeVerifyAndDeriveKeys(int ctx, uint* keys, int challenge, int extra, uint* output)`
*   **Description:** Handshake verify + key derivation. Calls `SakeCrypto_HandshakeWrapper` to derive keys, then `SakeCrypto_VerifyMessage` to validate derived material. Copies 20 bytes from challenge.

### 5.18. `SakeUtil_GenerateRandomIterationCount`
*   **Address:** `0x00015c68`
*   **Signature:** `void SakeUtil_GenerateRandomIterationCount(char* output)`
*   **Description:** Reads 1 random byte from `/dev/urandom`, masks with `& 3`, adds 1. Result is random value 1-4 used as iteration count for key confirmation.

### 5.19. `SakeSecureMessage_GetSequenceByte`
*   **Address:** `0x0001500c`
*   **Signature:** `uint32_t SakeSecureMessage_GetSequenceByte(int msgStruct, byte* output)`
*   **Description:** Extracts sequence byte from secure message. Reads offset at `+0x20`, subtracts 3, bounds-checks `< 0x1D`, returns byte at that index.

### 5.20. `SakeClient_DecryptAndValidateServerPermit`
*   **Address:** `0x0001553c`
*   **Signature:** `void SakeClient_DecryptAndValidateServerPermit(int encData, int keyData, int verifyData, uint* output)`
*   **Description:** Decrypts server permit. Calls `SakeCrypto_AES_ECB_SingleBlockEncrypt`, then `SakeCrypto_VerifyMessage`, extracts byte fields, validates state, copies 10 bytes to output.

### 5.21. `SakeUtil_IsChallengeBufferEmpty`
*   **Address:** `0x00015f04`
*   **Signature:** `void SakeUtil_IsChallengeBufferEmpty(void* buffer)`
*   **Description:** Checks if challenge buffer is empty. Verifies `+0x20 == 20` bytes, clears 20-byte buffer, compares with `memcmp`. Returns true if buffer is zero-filled (uninitialized).

### 5.22. `SakeUtil_FillChallengeWithRandom`
*   **Address:** `0x00015c4e`
*   **Signature:** `uint32_t SakeUtil_FillChallengeWithRandom(int buffer)`
*   **Description:** Fills challenge buffer with random. Checks if length < 20, sets to 20, calls `SakeUtil_ReadRandomBytes` to fill remaining bytes from `/dev/urandom`.

### 5.23. `SakeCrypto_InitCipherState`
*   **Address:** `0x00014dec`
*   **Signature:** `void SakeCrypto_InitCipherState(uint* state, uint mode, int key, uint* iv1, uint* iv2)`
*   **Description:** Initializes 48-byte cipher state struct. Sets mode flag, copies 16-byte key, sets block size `0x100`, zeroes sequence counters.

### 5.24. `SakeKeyDB_IsValidDeviceType`
*   **Address:** `0x00015f5c`
*   **Signature:** `bool SakeKeyDB_IsValidDeviceType(int deviceType)`
*   **Description:** Returns `(param_1 - 1) < 7`. Checks if device type byte is in valid range 1-7.

### 5.25. `SakeCrypto_FindAlgorithmDescriptor`
*   **Address:** `0x00016ce8`
*   **Signature:** `int SakeCrypto_FindAlgorithmDescriptor(int id, int mode, int blockSize)`
*   **Description:** Walks crypto algorithm descriptor table at `+0x1c`, matches by algorithm ID, mode, and block size. Returns matching descriptor or NULL.

### 5.26. `SakeCrypto_ExecuteCipherVtableOp`
*   **Address:** `0x00016dac`
*   **Signature:** `uint32_t SakeCrypto_ExecuteCipherVtableOp(int* cipherCtx, int extra, int blockSize, int mode)`
*   **Description:** Reads cipher vtable pointer at `+0x1c`, dispatches to function at `+0x0C` (encrypt) or `+0x10` (decrypt) based on mode flag. Indirect call through vtable.

### 5.27. `SakeCrypto_DispatchBlockCipher`
*   **Address:** `0x00016bc8`
*   **Signature:** `uint32_t SakeCrypto_DispatchBlockCipher(int ctx, int mode, int input, int output)`
*   **Description:** Block cipher dispatcher. If mode == 1, calls `SakeCrypto_AES_EncryptBlock` (ECB); otherwise calls `SakeCrypto_AES_TTable_EncryptBlock` (T-table optimized).

### 5.28. `SakeCrypto_AES_TTable_EncryptBlock`
*   **Address:** `0x00016890`
*   **Signature:** `uint32_t SakeCrypto_AES_TTable_EncryptBlock(int* keySchedule, uint* input, byte* output)`
*   **Description:** Full AES T-table encryption. Uses 4 lookup tables (Te0-Te3) at `DAT_00016bb4`-`DAT_00016bc0`, S-box at `DAT_00016bc4`. 10/12/14 round unrolled loop. Standard Rijndael T-table optimization.

### 5.29. `SakeCrypto_AES_ECB_SingleBlockEncrypt`
*   **Address:** `0x000161a4`
*   **Signature:** `void SakeCrypto_AES_ECB_SingleBlockEncrypt(int keyData, int inputBlock, int outputBlock)`
*   **Description:** AES-ECB single block encrypt. Allocates 280-byte AES context, expands key via `SakeCrypto_AES_KeyExpansion_Inferred` with 128-bit block size (`0x80`), encrypts via `SakeCrypto_DispatchBlockCipher`.

### 5.30. `SakeCrypto_AES_CTR_DecryptBlock`
*   **Address:** `0x00016124`
*   **Signature:** `void SakeCrypto_AES_CTR_DecryptBlock(uint* keyData, int ivData, int stateCtx, int outputState, int outputInfo)`
*   **Description:** AES-CTR decrypt block. Allocates 280-byte AES context, expands key, copies 16-byte IV/nonce, calls `SakeCrypto_AES_CTR_Transform` to decrypt block.

### 5.31. `SakeCrypto_DispatchCipherOperation`
*   **Address:** `0x00016e5c`
*   **Signature:** `int SakeCrypto_DispatchCipherOperation(int* cipherCtx, int inputLen, int dataLen, int outputLen, int* written)`
*   **Description:** Master cipher dispatcher. Checks algorithm type at `+4`, mode at `+0x18`, block alignment, dispatches via vtable function pointers at `+0x1c`. Handles ECB, CBC, CTR modes.

### 5.32. `SakeCrypto_ClearAESContext`
*   **Address:** `0x00016220`
*   **Signature:** `void SakeCrypto_ClearAESContext(int* context)`
*   **Description:** Clears 280-byte AES context structure via `__aeabi_memclr4`.

### 5.33. `SakeCrypto_ResetAESContext`
*   **Address:** `0x0001622e`
*   **Signature:** `void SakeCrypto_ResetAESContext(int* context)`
*   **Description:** Resets 280-byte AES context to zero.

### 5.34. `SakeCrypto_ComputeCMAC`
*   **Address:** `0x00015fe4`
*   **Signature:** `void SakeCrypto_ComputeCMAC(int* buffer)`
*   **Description:** Clears 60-byte buffer structure via `__aeabi_memclr4`.

### 5.35. `SakeCrypto_ResetBuffer`
*   **Address:** `0x00015eec`
*   **Signature:** `void SakeCrypto_ResetBuffer(int* buffer)`
*   **Description:** Resets generic buffer via `__aeabi_memclr4`.

### 5.36. `SakeKeyDB_GetEntryByte`
*   **Address:** `0x00015328`
*   **Signature:** `byte SakeKeyDB_GetEntryByte(int entry)`
*   **Description:** Returns single byte from key database entry at offset `+4` of the structure.

### 5.37. `SakeKeyDB_ValidateBufferState`
*   **Address:** `0x00015ec6`
*   **Signature:** `void SakeKeyDB_ValidateBufferState(int state)`
*   **Description:** Validates buffer state by calling `SakeKeyDB_IsValidDeviceType` on the state value.

### 5.38. `SakeKeyDB_LookupAndValidateType`
*   **Address:** `0x00015336`
*   **Signature:** `int SakeKeyDB_LookupAndValidateType(int* dbPtr, int deviceType)`
*   **Description:** Calls `SakeKeyDB_FindEntryByType` then `SakeKeyDB_IsValidDeviceType` to validate the result.

---

## 6. End-to-End Handshake & Secure Messaging Protocol Flow

Reimplementing a compatible SAKE client requires reproducing this exact execution flow:

```
    Client (Android)                                     Server (Device)
           |                                                    |
           | 1. SakeClient_GenerateChallenge()                  |
           |    Generates 20-Byte Rc                            |
           |                                                    |
           | ---------- Rc (Client Challenge) ------------->    |
           |                                                    |
           |                                                    | 2. Generates 20-Byte Rs
           |                                                    |    and looks up K_root
           |                                                    |
           | <--------- Rs (Server Challenge) + Auth --------   |
           |                                                    |
           | 3. SakeKeyDB_FindEntryByType()                     |
           |    Locates 16-byte K_root (Key 2)                  |
           |                                                    |
           | 4. SakeCrypto_VerifyHandshakeStep1()               |
           |    Decrypts and validates peer proof              |
           |                                                    |
           | ---------- Authenticated Session Established ----> |
           |                                                    |
           | 5. SakeCrypto_EncryptSignMessage()                 |
           |    Applies AES-128-CTR + 16-bit CMAC               |
           |                                                    |
```

### 6.1. Reimplementation Specifications
1.  **Handshake Verification Key ($K_{root}$):** To derive correct handshake proof payloads, extract the pre-shared secret key from **Key 2 (offset `0x17`)** of the device's corresponding 81-byte database row.
2.  **Ciphertext Frame Format:** 
    Secure GATT payloads are packed as:
    ```
    +--------------------------------+--------------------------+---------------------+
    | Encrypted Payload (AES-CTR)    | Sequence byte (CTR LS)   | 16-bit Truncated MAC|
    |          N Bytes               |          1 Byte          |       2 Bytes       |
    +--------------------------------+--------------------------+---------------------+
    ```
3.  **Authentication Verification:**
    During message validation, extract the trailing 2 bytes, run the standard CMAC verification over the encrypted body with the matching sequence state, apply the $GF(2^8)$ doubling logic, and assert that the derived high 16 bits match the appended MAC bytes.

---

## 7. Permit Subsystem (`SAKE_PERMIT_S`)

The permit subsystem handles the creation, encryption, signing, decryption, and authentication of **permits** — cryptographic tokens exchanged during the handshake to establish trust between client and server.

### 7.1. Permit Structure (`SAKE_PERMIT_S`)

```c
#pragma pack(push, 1)
typedef struct {
    uint32_t version;                     // +0x00: Permit version (SAKE_PERMIT_VERSION_E)
    uint32_t deviceType;                  // +0x04: Device type identifier (1-7)
    uint8_t  proprietaryBytes[10];        // +0x08: 10 proprietary bytes (device-specific)
    uint16_t reserved;                    // +0x12: Reserved/padding
} SAKE_PERMIT_S;                          // Total: 0x14 (20 bytes)
#pragma pack(pop)
```

### 7.2. Permit Error Strings

The following error strings are embedded in `.rodata` and thrown during permit operations:

| Address | String | Context |
|:---|:---|:---|
| `0x00019a59` | `"Attempt to dereference null SAKE_PERMIT_VERSION_E"` | Null version check |
| `0x00019e98` | `"The session key could not be used to receive the permit"` | Decryption failure |
| `0x00019ed0` | `"The permit could not be secured for sending"` | Encrypt+sign failure |
| `0x00019efc` | `"The permit could not be padded for sending"` | Padding failure |
| `0x00019f27` | `"The permit received is not padded"` | Padding validation |
| `0x00019f49` | `"The permit received is invalid"` | General validation |
| `0x00019f68` | `"The permit received is issued to a different device type"` | Device type mismatch |

### 7.3. Permit Functions

#### 7.3.1. `SakePermit_InitStruct`
*   **Address:** `0x00015494`
*   **Signature:** `void SakePermit_InitStruct(SAKE_PERMIT_S* permit, uint32_t version)`
*   **Description:** Initializes a 20-byte `SAKE_PERMIT_S` structure. Sets `version` at `+0x00`, zeroes `deviceType`, `proprietaryBytes`, and `reserved`. Called by `Sake_Permit_Init` JNI.

#### 7.3.2. `SakePermit_EncryptAndSign`
*   **Address:** `0x000154a4`
*   **Signature:** `void SakePermit_EncryptAndSign(SAKE_PERMIT_S* permit, int keyData, int macKey, int output)`
*   **Description:** Encrypts and signs a permit for transmission:
    1. Extracts `version` (byte 0), `deviceType` (byte 1), and 10 `proprietaryBytes` (bytes 2-11) from the permit.
    2. Calls `SakeCrypto_ComputeCMAC` to compute MAC over the 12-byte payload.
    3. Calls `SakeCrypto_VerifyHandshakeStep1` to AES-ECB encrypt the permit block.

#### 7.3.3. `SakeClient_DecryptAndValidateServerPermit`
*   **Address:** `0x0001553c`
*   **Signature:** `void SakeClient_DecryptAndValidateServerPermit(int encData, int keyData, int macKey, uint* output)`
*   **Description:** Decrypts and validates a server permit:
    1. AES-ECB decrypts the encrypted permit via `SakeCrypto_AES_ECB_SingleBlockEncrypt`.
    2. Validates MAC via `SakeCrypto_ComputeCMAC`.
    3. Extracts `version` (byte 0), `deviceType` (byte 1), and 10 `proprietaryBytes` (bytes 2-11).
    4. Validates `deviceType` is in range 1-7 via `SakeKeyDB_IsValidDeviceType`.
    5. Copies 10 proprietary bytes to output at `+2`.

#### 7.3.4. `SakeClient_GetServerPermit`
*   **Address:** `0x00014d74`
*   **Signature:** `SAKE_PERMIT_S* SakeClient_GetServerPermit(SAKE_CLIENT_S* client)`
*   **Description:** Returns pointer to server permit at `client + 0x1c` if `isSecureLinkEstablished` at `+0x70` is set. Returns `NULL` otherwise.

#### 7.3.5. `SakeServer_GetClientPermit`
*   **Address:** `0x00015a54`
*   **Signature:** `SAKE_PERMIT_S* SakeServer_GetClientPermit(SAKE_SERVER_S* server)`
*   **Description:** Returns pointer to client permit at `server + 0x1c` if `isSecureLinkEstablished` at `+0xa0` is set. Returns `NULL` otherwise.

### 7.4. Secure Link Functions

#### 7.4.1. `SakeClient_SecureForSending`
*   **Address:** `0x00014d50`
*   **Signature:** `uint32_t SakeClient_SecureForSending(SAKE_CLIENT_S* client)`
*   **Description:** If `isSecureLinkEstablished(+0x70)` is set, calls `SakeCrypto_EncryptSignAndIncrementSequence` at `client + 0x40` to encrypt an outgoing message.

#### 7.4.2. `SakeClient_UnsecureAfterReceiving`
*   **Address:** `0x00014d62`
*   **Signature:** `uint32_t SakeClient_UnsecureAfterReceiving(SAKE_CLIENT_S* client)`
*   **Description:** If `isSecureLinkEstablished(+0x70)` is set, calls `SakeCrypto_PerformEncryptDecrypt` at `client + 0x40` to decrypt an incoming message.

#### 7.4.3. `SakeServer_SecureForSending`
*   **Address:** `0x00015a30`
*   **Signature:** `uint32_t SakeServer_SecureForSending(SAKE_SERVER_S* server)`
*   **Description:** If `isSecureLinkEstablished(+0xa0)` is set, calls `SakeCrypto_EncryptSignAndIncrementSequence` at `server + 0x70` to encrypt an outgoing message.

#### 7.4.4. `SakeServer_UnsecureAfterReceiving`
*   **Address:** `0x00015a42`
*   **Signature:** `uint32_t SakeServer_UnsecureAfterReceiving(SAKE_SERVER_S* server)`
*   **Description:** If `isSecureLinkEstablished(+0xa0)` is set, calls `SakeCrypto_PerformEncryptDecrypt` at `server + 0x70` to decrypt an incoming message.

### 7.5. Server State Machine (Permit Flow)

The server handshake state machine processes permits through these states:

#### 7.5.1. `SakeServer_ProcessState1_InitOrReset` (State 1)
*   **Address:** `0x00015620`
*   **Description:** Checks if challenge buffer is empty. If empty, gets device type from `+0x68`, calls `SakeServer_SetDefaultState` to initialize. Routes to state 3 (exchange) or state 6 (finalize).

#### 7.5.2. `SakeServer_ProcessState2_Exchange` (State 2)
*   **Address:** `0x00015692`
*   **Description:** Parses client challenge via `SakeServer_ParseClientChallenge`. Looks up key DB entry. Derives handshake keys via `SakeServer_DeriveHandshakeKeys`. Generates server challenge.

#### 7.5.3. `SakeServer_ProcessState3_DeriveAndVerify` (State 3)
*   **Address:** `0x000157a4`
*   **Description:** Performs key confirmation via `SakeClient_PerformKeyConfirmation`. Verifies key derivation via `SakeServer_VerifyKeyDerivation`. Verifies handshake proof. Initializes cipher state at `+0x38`. Encrypts+signs permit via `SakeCrypto_EncryptSignAndIncrementSequence`.

#### 7.5.4. `SakeServer_ProcessState4_DecryptPermit` (State 4)
*   **Address:** `0x000158d4`
*   **Description:** Checks challenge length == 20. Looks up key DB. Decrypts via `SakeCrypto_PerformEncryptDecrypt`. Validates server permit via `SakeClient_DecryptAndValidateServerPermit`. Copies secure link state to `+0x70`. Sets `isSecureLinkEstablished` at `+0xa0`.

#### 7.5.5. `SakeServer_ProcessState6_Finalize` (State 6)
*   **Address:** `0x00015710`
*   **Description:** Reads 16 random bytes. Initializes cipher state at `+0x38`. Encrypts+signs via `SakeCrypto_EncryptSignAndIncrementSequence`. Error states: `0x0D` (random fail), `0x0F` (encrypt fail).

#### 7.5.6. `SakeServer_DeriveHandshakeKeys`
*   **Address:** `0x00015dc0`
*   **Description:** Generates server challenge via `SakeClient_GenerateChallenge`. Calls `SakeCrypto_HandshakeWrapper` to derive session keys from client+server challenges and key material.

#### 7.5.7. `SakeServer_ParseClientChallenge`
*   **Address:** `0x00015aae`
*   **Description:** Extracts 8 bytes challenge (`+0`), device type byte (`+0x10`). Validates device type 1-7 via `SakeKeyDB_IsValidDeviceType`. Returns 1 on success, 0 on failure.

#### 7.5.8. `SakeServer_VerifyKeyDerivation`
*   **Address:** `0x00015bd4`
*   **Description:** Checks challenge length == 20. Calls `SakeCrypto_HandshakeVerifyAndDeriveKeys`. Then `SakeCrypto_Memcmp` to verify derived key matches expected.

#### 7.5.9. `SakeServer_SetDefaultState`
*   **Address:** `0x00015eb8`
*   **Description:** Sets device type (`+0`), state (`+1`). Fills challenge buffer with random bytes via `SakeUtil_FillChallengeWithRandom`. Sets buffer length to 2 at `+0x20`.

---

## 8. Reconstructed Struct Layouts (Ghidra-Verified)

All structs below have been created in Ghidra's datatype system and applied to function parameters.

### 8.1. `SAKE_CLIENT_S` (120 bytes, Ghidra-verified)

```c
typedef struct {
    uint32_t currentState;                // +0x00: Current state machine index (1-8)
    uint32_t lowSequenceNumber;           // +0x04: Incremented per message (Counter Low)
    uint32_t highSequenceNumber;          // +0x08: Counter High for 64-bit sequence tracking
    uint8_t  localChallenge[20];          // +0x0C: Locally generated 20-byte random challenge (Rc)
    uint8_t  remoteChallenge[20];         // +0x20: Received 20-byte remote challenge (Rs)
    uint32_t deviceType;                  // +0x34: Device type identifier
    void*    cryptoVtablePtr;             // +0x38: Points to the cryptosystem descriptor vtable (0x0001de04)
    uint32_t dataLength;                  // +0x3C: Working buffer length
    SAKE_SECURE_LINK_S secureLink;        // +0x40: Secure link cipher state (48 bytes)
    uint8_t  isSecureLinkEstablished;     // +0x70: Flag: 1 = secure link active
    uint32_t handshakeStatus;             // +0x74: Error/Status flags (2 = Error, 8 = Success)
} SAKE_CLIENT_S;                          // Total: 0x78 (120 bytes)
```

### 8.2. `SAKE_SERVER_S` (168 bytes, Ghidra-verified)

```c
typedef struct {
    uint32_t currentState;                // +0x00: Current state machine index
    uint8_t  localChallenge[20];          // +0x04: Server challenge
    uint8_t  remoteChallenge[20];         // +0x18: Client challenge
    SAKE_PERMIT_S clientPermit;           // +0x1C: Client permit (20 bytes, overlaps with remoteChallenge)
    uint32_t deviceType;                  // +0x30: Client device type
    void*    cryptoVtablePtr;             // +0x34: Crypto vtable pointer
    SAKE_SECURE_LINK_S cipherState;       // +0x38: Cipher state for handshake
    uint8_t  keyDatabase[48];             // +0x68: Key database reference
    SAKE_SECURE_LINK_S secureLink;        // +0x70: Secure link cipher state
    uint8_t  isSecureLinkEstablished;     // +0xA0: Flag: 1 = secure link active
    uint32_t lastError;                   // +0xA4: Last error code
} SAKE_SERVER_S;                          // Total: 0xA8 (168 bytes)
```

### 8.3. `SAKE_PERMIT_S` (Final)

```c
#pragma pack(push, 1)
typedef struct {
    uint32_t version;                     // +0x00: Permit version (SAKE_PERMIT_VERSION_E)
    uint32_t deviceType;                  // +0x04: Device type identifier (1-7)
    uint8_t  proprietaryBytes[10];        // +0x08: 10 proprietary bytes (device-specific)
    uint16_t reserved;                    // +0x12: Reserved/padding
} SAKE_PERMIT_S;                          // Total: 0x14 (20 bytes)
#pragma pack(pop)
```

### 8.4. `SAKE_SECURE_LINK_S` (48 bytes, Ghidra-verified)

```c
typedef struct {
    uint32_t mode;                        // +0x00: Cipher mode flag (0 = decrypt, 1 = encrypt)
    uint32_t reserved1;                   // +0x04: Reserved
    uint32_t counterLow;                  // +0x08: Low 32 bits of 64-bit sequence counter
    uint32_t counterHigh;                 // +0x0C: High 32 bits of 64-bit sequence counter
    uint32_t blockSize;                   // +0x10: Block size (0x100 = 256-bit, 0x80 = 128-bit)
    uint32_t flags;                       // +0x14: Operation flags
    uint8_t  key[16];                     // +0x18: 16-byte session key
    uint32_t iv1;                         // +0x28: IV/nonce part 1
    uint32_t iv2;                         // +0x2C: IV/nonce part 2
} SAKE_SECURE_LINK_S;                     // Total: 0x30 (48 bytes)
```

### 8.5. `SAKE_SECURE_MESSAGE_S` (8 bytes, Ghidra-verified)

```c
typedef struct {
    uint8_t* pBytes;                      // +0x00: Pointer to message byte array
    uint32_t byteCount;                   // +0x04: Number of bytes in message
} SAKE_SECURE_MESSAGE_S;
```

### 8.6. Permit Wire Format

When a permit is encrypted for transmission over BLE:

```
+------------------------------------------+
| Encrypted Permit Block (AES-ECB)         |
|  12 bytes: version(1) + devType(1) +     |
|            proprietaryBytes(10)           |
+------------------------------------------+
| MAC Tag (AES-CMAC, truncated to 16-bit)  |
|  2 bytes                                  |
+------------------------------------------+
```

---

## 9. Ghidra Datatype System (Created & Applied)

All structs below have been created in Ghidra's datatype system and applied to function parameters across the binary.

| Struct Name | Size | Fields | Applied To |
|:---|:---|:---|:---|
| `SAKE_PERMIT_S` | 20 bytes | version, deviceType, proprietaryBytes[10], reserved | `SakePermit_InitStruct`, `SakePermit_EncryptAndSign`, `SakeClient_DecryptAndValidateServerPermit`, `SakeClient_GetServerPermit`, `SakeServer_GetClientPermit` |
| `SAKE_SECURE_MESSAGE_S` | 8 bytes | pBytes, byteCount | `SakeCrypto_EncryptSignMessage`, `sakeCrypto_DecryptAuthenticate_HighLevel`, `SakeCrypto_PerformEncryptDecrypt`, `SakeSecureMessage_GetSequenceByte`, `SakeCrypto_ComputeMACAndAppend`, `SakeClient_HandshakeHandler`, `SakeServer_HandshakeHandler` |
| `SAKE_SECURE_LINK_S` | 48 bytes | mode, counterLow, counterHigh, blockSize, flags, key[16], iv1, iv2 | `SakeCrypto_EncryptSignMessage`, `sakeCrypto_DecryptAuthenticate_HighLevel`, `SakeCrypto_PerformEncryptDecrypt`, `SakeCrypto_InitCipherState`, `SakeCrypto_EncryptMessage_HighLevel`, `SakeCrypto_AES_CTR_DecryptBlock` |
| `SAKE_CLIENT_S` | 120 bytes | currentState, lowSequenceNumber, highSequenceNumber, localChallenge[20], remoteChallenge[20], deviceType, cryptoVtablePtr, dataLength, secureLink, isSecureLinkEstablished, handshakeStatus | `SakeClient_HandshakeHandler`, `SakeClient_SecureForSending`, `SakeClient_UnsecureAfterReceiving`, `SakeClient_GetServerPermit` |
| `SAKE_SERVER_S` | 168 bytes | currentState, localChallenge[20], remoteChallenge[20], clientPermit, deviceType, cryptoVtablePtr, cipherState, keyDatabase[48], secureLink, isSecureLinkEstablished, lastError | `SakeServer_HandshakeHandler`, `SakeServer_SecureForSending`, `SakeServer_UnsecureAfterReceiving`, `SakeServer_GetClientPermit`, all server state handlers |

---

## 10. JNI Interface Functions (Permit-Related)

| JNI Function | Address | Internal Call | Description |
|:---|:---|:---|:---|
| `Sake_Permit_Init` | `0x000142f4` | `SakePermit_InitStruct` | Allocates and initializes 20-byte permit |
| `Sake_Permit_EncryptAndSign` | `0x00014360` | `SakePermit_EncryptAndSign` | Encrypts permit for transmission |
| `Sake_Permit_DecryptAndAuthenticate` | `0x00014372` | `SakeClient_DecryptAndValidateServerPermit` | Decrypts and validates received permit |
| `Sake_Client_GetServerPermit` | `0x000145e0` | `SakeClient_GetServerPermit` | Returns server permit pointer |
| `Sake_Server_GetClientPermit` | `0x000148f8` | `SakeServer_GetClientPermit` | Returns client permit pointer |
| `SAKE_CLIENT_S_serverPermit_get` | `0x00014488` | — | JNI getter for server permit |
| `SAKE_CLIENT_S_serverPermit_set` | `0x0001446e` | — | JNI setter for server permit |
| `SAKE_SERVER_S_clientPermit_get` | `0x000146f8` | — | JNI getter for client permit |
| `SAKE_SERVER_S_clientPermit_set` | `0x000146de` | — | JNI setter for client permit |
| `SAKE_PERMIT_S_version_get` | `0x00014280` | — | JNI getter for permit version |
| `SAKE_PERMIT_S_version_set` | `0x00014268` | — | JNI setter for permit version |
| `SAKE_PERMIT_S_deviceType_get` | `0x000142ac` | — | JNI getter for permit device type |
| `SAKE_PERMIT_S_deviceType_set` | `0x00014294` | — | JNI setter for permit device type |
| `SAKE_PERMIT_S_pProprietaryBytes_get` | `0x000142d4` | — | JNI getter for proprietary bytes pointer |
| `SAKE_PERMIT_S_pProprietaryBytes_set` | `0x000142be` | — | JNI setter for proprietary bytes pointer |
| `SAKE_PERMIT_PROPRIETARY_BYTE_COUNT_get` | `0x00014260` | — | Returns constant 10 |
| `new_SAKE_PERMIT_S` | `0x000142dc` | `malloc(0x14)` | Allocates new permit struct |
| `delete_SAKE_PERMIT_S` | `0x000142ec` | `free` | Frees permit struct |

---

## 11. SecureMessage Subsystem (Runtime Encryption/Decryption)

The SecureMessage subsystem is the **data plane** — it handles encrypting and decrypting application-level messages AFTER the handshake establishes a secure link. This is what the Java application actually uses to send/receive data over BLE.

### 10.1. Secure Message Wire Format

```
+---------------------------------------------------+
| Encrypted Payload (AES-128-CTR)                   |
|   N bytes (original data length)                  |
+---------------------------------------------------+
| Sequence Byte (CTR counter low byte)              |
|   1 byte                                          |
+---------------------------------------------------+
| Truncated MAC (AES-CMAC, 16-bit)                  |
|   2 bytes                                         |
+---------------------------------------------------+
| Total overhead: 3 bytes per message               |
+---------------------------------------------------+
```

### 10.2. Message Size Constraints

*   **MIN:** `MIN_SAKE_SECURE_MESSAGE_BYTE_COUNT` (JNI constant at `0x0001401c`)
*   **MAX:** `MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT` (JNI constant at `0x00014022`)
*   **Effective max payload:** 30 bytes (`0x1E`) — checked at `SakeCrypto_EncryptSignMessage`
*   **Effective min payload:** 3 bytes — checked at `sakeCrypto_DecryptAuthenticate_HighLevel`
*   **Max wire size:** 33 bytes (30 payload + 3 overhead)

### 10.3. Encrypt Flow (`Sake_SecureMessage_EncryptAndSign`)

```
JNI Layer
  └─ SakeCrypto_EncryptSignMessage @ 0x00015028
       ├─ Check dataLen < 0x1E (30 bytes)
       ├─ Set outputLen = dataLen + 3
       ├─ SakeCrypto_EncryptMessage_HighLevel @ 0x00016078
       │    ├─ SakeCrypto_ClearAESContext (280-byte context)
       │    ├─ SakeCrypto_AES_ProcessBlock (mode 0x80 = 128-bit)
       │    ├─ Copy 16-byte IV/nonce
       │    └─ SakeCrypto_AES_CTR_Transform (encrypt payload)
       ├─ SakeCrypto_ComputeMACAndAppend @ 0x000150c8
       │    ├─ Copy 16-byte key
       │    ├─ Copy encrypted payload to MAC buffer
       │    └─ SakeCrypto_ComputeCMAC (compute AES-CMAC)
       ├─ Write sequence byte at (output + dataLen)
       └─ Write 2-byte MAC at (output + dataLen + 1)
```

### 10.4. Decrypt Flow (`Sake_SecureMessage_DecryptAndAuthenticate`)

```
JNI Layer
  └─ sakeCrypto_DecryptAuthenticate_HighLevel @ 0x0001512c
       ├─ Check dataSize 3-32 bytes
       ├─ Set outputLen = dataSize - 3
       ├─ SakeCrypto_ComputeMACAndAppend @ 0x000150c8
       │    ├─ Copy 16-byte key
       │    ├─ Copy encrypted payload to MAC buffer
       │    └─ SakeCrypto_ComputeCMAC (compute AES-CMAC)
       ├─ Compare computed MAC (16-bit) with stored MAC
       └─ If match: SakeCrypto_AES_CTR_DecryptBlock @ 0x00016124
            ├─ SakeCrypto_ClearAESContext
            ├─ SakeCrypto_AES_KeyExpansion_Inferred
            └─ SakeCrypto_AES_CTR_Transform (decrypt payload)
```

### 10.5. SecureMessage Functions

#### 10.5.1. `SakeCrypto_EncryptSignMessage`
*   **Address:** `0x00015028`
*   **Signature:** `void SakeCrypto_EncryptSignMessage(int cryptoContext, byte data, int outputBuffer, int sequenceNumber, int outputState)`
*   **Description:** The master encrypt+sign function. Checks `dataLen < 0x1E`, sets `outputLen = dataLen + 3`. Calls `SakeCrypto_EncryptMessage_HighLevel` for AES-CTR encryption, then `SakeCrypto_ComputeMACAndAppend` for MAC. Appends sequence byte at `-3` offset and 2-byte MAC at `-2` offset.

#### 10.5.2. `sakeCrypto_DecryptAuthenticate_HighLevel`
*   **Address:** `0x0001512c`
*   **Signature:** `void sakeCrypto_DecryptAuthenticate_HighLevel(int inputBuffer, int encryptedData, uint dataSize, int outputState)`
*   **Description:** The master decrypt+authenticate function. Checks `dataSize` 3-32, sets `outputLen = dataSize - 3`. Calls `SakeCrypto_ComputeMACAndAppend` to verify MAC, compares 16-bit tag. If valid, calls `SakeCrypto_AES_CTR_DecryptBlock` to decrypt.

#### 10.5.3. `SakeCrypto_ComputeMACAndAppend`
*   **Address:** `0x000150c8`
*   **Signature:** `void SakeCrypto_ComputeMACAndAppend(int messageContext, int messageData, int outputBuffer, int processFlag, int outputStateInfo)`
*   **Description:** Computes AES-CMAC over the encrypted payload. Copies 16-byte key, copies payload to MAC buffer, calls `SakeCrypto_ComputeCMAC` to compute MAC. Returns 16-bit truncated MAC.

#### 10.5.4. `SakeCrypto_EncryptMessage_HighLevel`
*   **Address:** `0x00016078`
*   **Signature:** `void SakeCrypto_EncryptMessage_HighLevel(uint* cryptoContext, int data, int outputBuffer, int sequenceNumber, int outputState)`
*   **Description:** AES-CTR encryption wrapper. Clears 280-byte AES context, processes block with mode `0x80` (128-bit), copies 16-byte IV/nonce, calls `SakeCrypto_AES_CTR_Transform` to encrypt, resets context.

#### 10.5.5. `SakeCrypto_PerformEncryptDecrypt`
*   **Address:** `0x00014f44`
*   **Signature:** `void SakeCrypto_PerformEncryptDecrypt(int* cipherState, int messageBuffer, int outputBuffer)`
*   **Description:** Handshake-level encrypt/decrypt. Extracts sequence byte via `SakeSecureMessage_GetSequenceByte`, updates 64-bit counter (low at `+0x10`, high at `+0x14`), calls `sakeCrypto_LowLevelPrimitive` to build CTR block, then `sakeCrypto_DecryptAuthenticate_HighLevel`. Increments sequence on success.

#### 10.5.6. `sakeCrypto_LowLevelPrimitive`
*   **Address:** `0x00014ed0`
*   **Signature:** `void sakeCrypto_LowLevelPrimitive(byte* output, int keyData, uint seqLow, int seqHigh, uint mode, uint* key1, uint* key2)`
*   **Description:** Constructs 16-byte AES-CTR counter block from 64-bit sequence number. Big-endian encoding of sequence into counter bytes. Copies key material at offsets `+5` and `+9`. Zeroes unused bytes.

#### 10.5.7. `SakeSecureMessage_GetSequenceByte`
*   **Address:** `0x0001500c`
*   **Signature:** `uint32_t SakeSecureMessage_GetSequenceByte(int msgStruct, byte* output)`
*   **Description:** Extracts sequence byte from secure message. Reads offset at `+0x20`, subtracts 3, bounds-checks `< 0x1D`, returns byte at that index.

#### 10.5.8. `SakeCrypto_HandshakeWrapper`
*   **Address:** `0x00015d4c`
*   **Signature:** `void SakeCrypto_HandshakeWrapper(uint* challenge1, uint* challenge2, int keyData, int macKey, uint* output)`
*   **Description:** Handshake key derivation MAC. Copies 8 bytes from each challenge buffer, copies 16-byte key, calls `SakeCrypto_ComputeCMAC` to compute MAC over 32-byte (0x20) combined data. Returns 8-byte MAC.

#### 10.5.9. `SakeCrypto_InitCipherAndAllocateState`
*   **Address:** `0x00016ffc`
*   **Signature:** `int SakeCrypto_InitCipherAndAllocateState(int* cipherCtx, int mode, int extra)`
*   **Description:** Validates cipher context, calls `SakeCrypto_ExecuteCipherVtableOp`, allocates 0x24-byte state via `calloc`, zeroes first 16 bytes. Returns error code or 0.

#### 10.5.10. `SakeCrypto_ProcessCipherBlock`
*   **Address:** `0x00016f64`
*   **Signature:** `void SakeCrypto_ProcessCipherBlock(int* cipherCtx, int input, int output, int blockSize, int mode, int flags, int* written)`
*   **Description:** Validates context, calls `SakeCrypto_DispatchCipherOperation`, then `SakeCrypto_GetCipherOutputSize`. Adds output size to written count.

#### 10.5.11. `SakeCrypto_GetCipherOutputSize`
*   **Address:** `0x00016f24`
*   **Signature:** `int SakeCrypto_GetCipherOutputSize(int* cipherCtx, int mode, int* outputSize)`
*   **Description:** Returns 0 for mode 1 (ECB), checks mode 5 (CTR/CBC), returns error for mode 3. Sets output size based on algorithm type.

#### 10.5.12. `SakeCrypto_ValidateCipherContext`
*   **Address:** `0x00016e0c`
*   **Signature:** `int SakeCrypto_ValidateCipherContext(int* cipherCtx)`
*   **Description:** Checks algorithm type at `+4`, validates mode flags. Returns 0 if valid or error code `DAT_00016f60`.

---

## 12. JNI Interface Functions (SecureMessage-Related)

| JNI Function | Address | Internal Call | Description |
|:---|:---|:---|:---|
| `Sake_SecureMessage_EncryptAndSign` | `0x00014072` | `SakeCrypto_EncryptSignMessage` | Encrypts + signs message |
| `Sake_SecureMessage_DecryptAndAuthenticate` | `0x0001408e` | `sakeCrypto_DecryptAuthenticate_HighLevel` | Decrypts + verifies message |
| `Sake_SecureMessage_GetSequenceNumber` | `0x00014064` | `SakeSecureMessage_GetSequenceByte` | Extracts sequence byte |
| `SAKE_SECURE_MESSAGE_S_pBytes_get` | `0x0001403a` | — | JNI getter for message bytes |
| `SAKE_SECURE_MESSAGE_S_pBytes_set` | `0x00014028` | — | JNI setter for message bytes |
| `SAKE_SECURE_MESSAGE_S_byteCount_get` | `0x00014048` | — | JNI getter for byte count |
| `SAKE_SECURE_MESSAGE_S_byteCount_set` | `0x00014040` | — | JNI setter for byte count |
| `new_SAKE_SECURE_MESSAGE_S` | `0x0001404e` | `malloc` | Allocates new secure message |
| `delete_SAKE_SECURE_MESSAGE_S` | `0x0001405e` | `free` | Frees secure message |
| `MIN_SAKE_SECURE_MESSAGE_BYTE_COUNT_get` | `0x0001401c` | — | Returns minimum message size |
| `MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get` | `0x00014022` | — | Returns maximum message size |

---

## 13. SAKE_SECURE_MESSAGE_S Structure

```c
#pragma pack(push, 1)
typedef struct {
    uint8_t* pBytes;                      // +0x00: Pointer to message byte array
    uint32_t byteCount;                   // +0x04: Number of bytes in message
} SAKE_SECURE_MESSAGE_S;
#pragma pack(pop)
```

### 12.1. Secure Link State (Embedded in Client/Server)

The secure link cipher state is a 48-byte structure embedded at:
*   **Client:** `SAKE_CLIENT_S + 0x40`
*   **Server:** `SAKE_SERVER_S + 0x70`

```c
typedef struct {
    uint32_t mode;                        // +0x00: Cipher mode flag (0 = decrypt, 1 = encrypt)
    uint32_t sequenceCounterLow;          // +0x04: Low 32 bits of 64-bit sequence
    uint32_t sequenceCounterHigh;         // +0x08: High 32 bits of 64-bit sequence
    uint32_t blockSize;                   // +0x0C: Block size (0x100 = 256-bit, 0x80 = 128-bit)
    uint32_t reserved;                    // +0x10: Reserved
    uint8_t  iv[16];                      // +0x14: Initialization vector / nonce
    uint8_t  key[16];                     // +0x24: Session key
    uint8_t  macKey[16];                  // +0x34: MAC key
} SAKE_SECURE_LINK_S;                     // Total: 0x30 (48 bytes)
```

---

## 14. Complete Function Call Graph (SecureMessage Path)

```
Sake_SecureMessage_EncryptAndSign (JNI)
  └─ SakeCrypto_EncryptSignMessage
       ├─ SakeCrypto_EncryptMessage_HighLevel
       │    ├─ SakeCrypto_ClearAESContext
       │    ├─ SakeCrypto_AES_ProcessBlock (mode 0x80)
       │    └─ SakeCrypto_AES_CTR_Transform
       │         └─ SakeCrypto_AES_EncryptBlock
       └─ SakeCrypto_ComputeMACAndAppend
            └─ SakeCrypto_ComputeCMAC (AES-CMAC)

Sake_SecureMessage_DecryptAndAuthenticate (JNI)
  └─ sakeCrypto_DecryptAuthenticate_HighLevel
       ├─ SakeCrypto_ComputeMACAndAppend
       │    └─ SakeCrypto_ComputeCMAC (AES-CMAC)
       └─ SakeCrypto_AES_CTR_DecryptBlock
            ├─ SakeCrypto_ClearAESContext
            ├─ SakeCrypto_AES_KeyExpansion_Inferred
            └─ SakeCrypto_AES_CTR_Transform
                 └─ SakeCrypto_AES_EncryptBlock

SakeCrypto_PerformEncryptDecrypt (handshake)
  ├─ SakeSecureMessage_GetSequenceByte
  ├─ sakeCrypto_LowLevelPrimitive (build CTR block)
  └─ sakeCrypto_DecryptAuthenticate_HighLevel
       ├─ SakeCrypto_ComputeMACAndAppend
       └─ SakeCrypto_AES_CTR_DecryptBlock
```

---

## 15. Key Database Management

The key database stores pre-shared keys for device authentication. It uses a CRC32-protected binary format.

### 15.1. Database Format

```
+------------------------------------------+
| Header (6 bytes)                         |
|  +0x00: CRC32 (4 bytes, big-endian)      |
|  +0x04: Device type (1 byte)             |
|  +0x05: Entry count (1 byte)             |
+------------------------------------------+
| Entry 0 (81 bytes = 0x51)                |
|  +0x06: Entry type (1 byte)              |
|  +0x07: Key 1 (16 bytes)                 |
|  +0x17: Key 2 (16 bytes)                 |
|  +0x27: Key 3 (16 bytes)                 |
|  +0x37: Key 4 (16 bytes)                 |
|  +0x47: Key 5 (16 bytes)                 |
+------------------------------------------+
| Entry 1 (81 bytes)                       |
|  ...                                     |
+------------------------------------------+
```

### 15.2. Key Database Functions

#### 15.2.1. `SakeKeyDB_CreateDatabase`
*   **Address:** `0x0001538a`
*   **Signature:** `uint SakeKeyDB_CreateDatabase(int* dbPtr, int deviceType, int size, uint type)`
*   **Description:** Creates a new key database. Validates device type, checks type > 5, sets size and type in header, initializes entry at +4, sets entry count to 0, calls `SakeKeyDB_ResetAndRecomputeCRC`.

#### 15.2.2. `SakeKeyDB_OpenDatabase`
*   **Address:** `0x00015290`
*   **Signature:** `void SakeKeyDB_OpenDatabase(int* dbPtr, int dataBuffer, uint size)`
*   **Description:** Opens an existing key database. Validates device type at +4, checks size > 5, validates CRC32 via `SakeKeyDB_ValidateCRC`, iterates entries to validate each device type. Sets dbPtr and capacity on success.

#### 15.2.3. `SakeKeyDB_AddEntry`
*   **Address:** `0x000153ce`
*   **Signature:** `uint SakeKeyDB_AddEntry(int* dbPtr, int data, int size)`
*   **Description:** Adds a new entry to the key database. Validates device type, checks capacity `(entryCount+1)*0x51+6 <= capacity`. Copies 5 keys (16 bytes each) at entry+0x10, +0x20, +0x30, +0x40, +0x50. Increments entry count, recomputes CRC.

#### 15.2.4. `SakeKeyDB_CalculateEntryOffset`
*   **Address:** `0x0001548a`
*   **Signature:** `int SakeKeyDB_CalculateEntryOffset(int keyValue)`
*   **Description:** Returns `keyValue * 0x51 + 6`. Each entry is 81 bytes, header is 6 bytes.

#### 15.2.5. `SakeKeyDB_ResetAndRecomputeCRC`
*   **Address:** `0x00015226`
*   **Signature:** `void SakeKeyDB_ResetAndRecomputeCRC(int* dbPtr)`
*   **Description:** Calls `SakeKeyDB_ComputeCRC32` over `(entryCount * 0x51 + 2)` bytes starting at +4. Writes 4-byte CRC to database header bytes 0-3 (big-endian).

#### 15.2.6. `SakeKeyDB_ComputeCRC32`
*   **Address:** `0x000174ec`
*   **Signature:** `uint SakeKeyDB_ComputeCRC32(uint initial, byte* data, int length)`
*   **Description:** Standard CRC32 computation using table at `DAT_00017514`. Initial value `~0`, XORs each byte with low byte of accumulator, looks up in 256-entry table, shifts right 8. Returns `~result`.

#### 15.2.7. `SakeKeyDB_ValidateCRC`
*   **Address:** `0x00015258`
*   **Signature:** `bool SakeKeyDB_ValidateCRC(int* dbPtr)`
*   **Description:** Validates CRC32 of key database. Computes CRC via `SakeKeyDB_ComputeCRC32`, compares with stored 4-byte CRC at header bytes 0-3 (big-endian). Returns true if match.

---

## 16. UserMessage Subsystem

The UserMessage subsystem handles unencrypted application-level messages — what the app uses before encryption is established.

### 16.1. `SAKE_USER_MESSAGE_S` Structure (36 bytes, Ghidra-verified)

```c
typedef struct {
    uint8_t  pBytes[29];                  // +0x00: Message byte buffer (max 29 bytes)
    uint32_t byteCount;                   // +0x20: Number of bytes in message
} SAKE_USER_MESSAGE_S;                    // Total: 0x24 (36 bytes)
```

### 16.2. Size Constraints

*   **MAX:** `MAX_SAKE_USER_MESSAGE_BYTE_COUNT` = 0x1D (29 bytes)
*   **Struct size:** 0x24 (36 bytes) — allocated via `calloc(1, 0x24)`

### 16.3. UserMessage JNI Functions

| JNI Function | Address | Description |
|:---|:---|:---|
| `SakeJNI_GetMaxUserMessageByteCount` | `0x000140a0` | Returns 0x1D (29 bytes) |
| `SakeJNI_SetUserMessageBytes` | `0x000140a6` | Copies 29 bytes to pBytes buffer |
| `SakeJNI_GetUserMessageBytes` | `0x000140b8` | Returns pointer to pBytes buffer |
| `SakeJNI_SetUserMessageByteCount` | `0x000140be` | Sets byteCount at +0x20 |
| `SakeJNI_GetUserMessageByteCount` | `0x000140c6` | Returns byteCount at +0x20 |
| `SakeJNI_AllocUserMessage` | `0x000140cc` | Allocates 36 bytes via calloc |
| `SakeJNI_FreeUserMessage` | `0x000140dc` | Frees UserMessage struct |

---

## 17. Error Handling Infrastructure

### 17.1. Error Code Range

*   **INVALID:** 0 (error state)
*   **NO_ERROR:** 1 (success state)
*   **Valid range:** 1-19 (0x13 = LAST)
*   **NULL pointer:** Returns error code 2

### 17.2. Error Strings (Embedded in `.rodata`)

| Address | String | Context |
|:---|:---|:---|
| `0x00019a24` | `"Attempt to dereference null SAKE_DEVICE_TYPE_E const"` | Null device type |
| `0x00019a59` | `"Attempt to dereference null SAKE_PERMIT_VERSION_E"` | Null permit version |
| `0x00019a8b` | `"Attempt to dereference null SAKE_DEVICE_TYPE_E"` | Null device type |
| `0x00019aba` | `"Attempt to dereference null SAKE_CLIENT_STATE_E"` | Null client state |
| `0x00019aea` | `"Attempt to dereference null SAKE_CHALLENGE_S"` | Null challenge |
| `0x00019b17` | `"Attempt to dereference null SAKE_INITIALIZATION_VECTOR_S"` | Null IV |
| `0x00019b50` | `"Attempt to dereference null SAKE_SECURE_LINK_S"` | Null secure link |
| `0x00019b7f` | `"Attempt to dereference null SAKE_SERVER_STATE_E"` | Null server state |
| `0x00019baf` | `"java/lang/OutOfMemoryError"` | JNI OOM exception |
| `0x00019c7d` | `"java/lang/UnknownError"` | JNI unknown error |
| `0x00019c94` | `"No error has occurred"` | No error message |
| `0x00019e98` | `"The session key could not be used to receive the permit"` | Permit decrypt fail |
| `0x00019ed0` | `"The permit could not be secured for sending"` | Permit encrypt fail |
| `0x00019efc` | `"The permit could not be padded for sending"` | Padding fail |
| `0x00019f27` | `"The permit received is not padded"` | Padding validation |
| `0x00019f49` | `"The permit received is invalid"` | General validation |
| `0x00019f68` | `"The permit received is issued to a different device type"` | Device type mismatch |
| `0x00019fa1` | `"The handshake error is invalid"` | Invalid error code |

### 17.3. Error Functions

#### 17.3.1. `SakeError_IsValidCode`
*   **Address:** `0x0001490c`
*   **Signature:** `bool SakeError_IsValidCode(int errorCode)`
*   **Description:** Returns `(errorCode - 1) < 0x13`. Error codes 1-19 are valid. 0 = invalid, 1 = no error.

#### 17.3.2. `SakeError_GetStringForCode`
*   **Address:** `0x00014918`
*   **Signature:** `char* SakeError_GetStringForCode(int errorCode)`
*   **Description:** Looks up error string from table at `DAT_00014930`. Returns pointer to string for error code (1-19).

#### 17.3.3. `SakeError_ParseStringToCode`
*   **Address:** `0x00014938`
*   **Signature:** `uint SakeError_ParseStringToCode(char* errorString)`
*   **Description:** Iterates error table (1-19), compares string via `strcmp`. Returns matching error code or 0 if not found.

#### 17.3.4. `SakeJNI_HandleKeyDatabaseError`
*   **Address:** `0x00014180`
*   **Signature:** `void SakeJNI_HandleKeyDatabaseError(int* errorContext, uint errorCode)`
*   **Description:** Error handler. Iterates error table at `DAT_000141d0`, calls vtable functions at +0x44, +0x18, +0x38 to report errors to Java layer.

#### 17.3.5. `SakeJNI_ClientGetLastError`
*   **Address:** `0x000145ee`
*   **Signature:** `uint SakeJNI_ClientGetLastError(JNIEnv* env, jobject obj, SAKE_CLIENT_S* client)`
*   **Description:** Returns `lastError` at client+0x74. Returns 2 if client pointer is NULL.

#### 17.3.6. `SakeJNI_ServerGetLastError`
*   **Address:** `0x00014906`
*   **Signature:** `uint SakeJNI_ServerGetLastError(JNIEnv* env, jobject obj, SAKE_SERVER_S* server)`
*   **Description:** Returns `lastError` at server+0xA4. Returns 2 if server pointer is NULL.

### 17.4. Handshake Error JNI Functions

| JNI Function | Address | Description |
|:---|:---|:---|
| `SakeJNI_GetHandshakeErrorInvalid` | `0x00013f90` | Returns 0 (INVALID) |
| `SakeJNI_GetHandshakeNoError` | `0x00013f94` | Returns 1 (NO_ERROR) |
| `SakeJNI_GetHandshakeErrorLast` | `0x00013f98` | Returns 0x13 (LAST) |
| `SakeJNI_HandshakeErrorIsValid` | `0x00013f9c` | Validates error code 1-19 |
| `SakeJNI_HandshakeErrorToString` | `0x00013fa8` | Converts error code to Java string |
| `SakeJNI_HandshakeErrorFromString` | `0x00013fca` | Parses Java string to error code |

---

## 18. Complete JNI API Surface

This section maps every JNI export to its internal implementation, based on decompilation and the extracted Android Java code.

### 18.1. Client Lifecycle

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Client_Init` | `0x000145a8` | — | `Sake_Client_Init` | Sets currentState=1, copies key DB pointer, clears isSecureLinkEstablished, sets handshakeStatus=1 |
| `Sake_Client_Destroy` | `0x000145b0` | `__aeabi_memclr8` | `Sake_Client_Destroy` | Zeroes 120 bytes (0x78) of client struct |

### 18.2. Client Handshake

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Client_Handshake` | `0x000145b6` | `SakeClient_HandshakeHandler` | `Sake_Client_Handshake` | Master handshake state machine. Routes to states 1-8 |
| `Sake_Client_GetLastError` | `0x000145ee` | — | `Sake_Client_GetLastError` | Returns lastError at client+0x74 |

### 18.3. Client Secure Messaging

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Client_SecureForSending` | `0x000145c0` | `SakeClient_SecureForSending` | `Sake_Client_SecureForSending` | Encrypts outgoing message |
| `Sake_Client_UnsecureAfterReceiving` | `0x000145d0` | `SakeClient_UnsecureAfterReceiving` | `Sake_Client_UnsecureAfterReceiving` | Decrypts incoming message |
| `Sake_Client_GetServerPermit` | `0x000145e0` | `SakeClient_GetServerPermit` | `Sake_Client_GetServerPermit` | Returns server permit pointer |

### 18.4. Server Lifecycle

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Server_Init` | `0x000148c0` | — | `Sake_Server_Init` | Sets currentState=1, copies key DB pointer, clears isSecureLinkEstablished, sets lastError=1 |
| `Sake_Server_Destroy` | `0x000148c8` | `__aeabi_memclr8` | `Sake_Server_Destroy` | Zeroes 168 bytes (0xA8) of server struct |

### 18.5. Server Handshake

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Server_Handshake` | `0x000148ce` | `SakeServer_HandshakeHandler` | `Sake_Server_Handshake` | Master handshake state machine. Routes to states 1-6 |
| `Sake_Server_GetLastError` | `0x00014906` | — | `Sake_Server_GetLastError` | Returns lastError at server+0xA4 |

### 18.6. Server Secure Messaging

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Server_SecureForSending` | `0x000148d8` | `SakeServer_SecureForSending` | `Sake_Server_SecureForSending` | Encrypts outgoing message |
| `Sake_Server_UnsecureAfterReceiving` | `0x000148e8` | `SakeServer_UnsecureAfterReceiving` | `Sake_Server_UnsecureAfterReceiving` | Decrypts incoming message |
| `Sake_Server_GetClientPermit` | `0x000148f8` | `SakeServer_GetClientPermit` | `Sake_Server_GetClientPermit` | Returns client permit pointer |

### 18.7. Key Database

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_KeyDatabase_Open` | `0x00014132` | `SakeKeyDB_OpenDatabase` | `Sake_KeyDatabase_Open` | Opens existing key database |
| `Sake_KeyDatabase_GetLocalDeviceType` | `0x00014142` | `SakeKeyDB_GetEntryByte` | `Sake_KeyDatabase_GetLocalDeviceType` | Returns device type from header |
| `Sake_KeyDatabase_HasRemoteDeviceType` | `0x0001415c` | `SakeKeyDB_LookupAndValidateType` | `Sake_KeyDatabase_HasRemoteDeviceType` | Checks if device type exists |
| `Sake_KeyDatabase_GetRemoteDeviceKeyByType` | `0x000141d4` | `SakeKeyDB_LookupEntryByType` | `Sake_KeyDatabase_GetRemoteDeviceKeyByType` | Gets key entry by device type |
| `Sake_KeyDatabase_Create` | `0x000141f8` | `SakeKeyDB_CreateDatabase` | `Sake_KeyDatabase_Create` | Creates new key database |
| `Sake_KeyDatabase_AddRemoteDeviceKey` | `0x00014224` | `SakeKeyDB_AddEntry` | `Sake_KeyDatabase_AddRemoteDeviceKey` | Adds key entry to database |
| `Sake_KeyDatabase_Clear` | `0x0001424c` | `SakeKeyDB_ResetAndRecomputeCRC` | `Sake_KeyDatabase_Clear` | Clears all entries, recomputes CRC |
| `Sake_KeyDatabase_GetSizeInBytes` | `0x00014252` | `SakeKeyDB_CalculateEntryOffset` | `Sake_KeyDatabase_GetSizeInBytes` | Returns database size in bytes |

### 18.8. SecureMessage

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_SecureMessage_EncryptAndSign` | `0x00014072` | `SakeCrypto_EncryptSignMessage` | `Sake_SecureMessage_EncryptAndSign` | Encrypts + signs message |
| `Sake_SecureMessage_DecryptAndAuthenticate` | `0x0001408e` | `sakeCrypto_DecryptAuthenticate_HighLevel` | `Sake_SecureMessage_DecryptAndAuthenticate` | Decrypts + verifies message |
| `Sake_SecureMessage_GetSequenceNumber` | `0x00014064` | `SakeSecureMessage_GetSequenceByte` | `Sake_SecureMessage_GetSequenceNumber` | Extracts sequence byte |

### 18.9. Permit

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `Sake_Permit_Init` | `0x000142f4` | `SakePermit_InitStruct` | `Sake_Permit_Init` | Initializes 20-byte permit |
| `Sake_Permit_EncryptAndSign` | `0x00014360` | `SakePermit_EncryptAndSign` | `Sake_Permit_EncryptAndSign` | Encrypts permit for transmission |
| `Sake_Permit_DecryptAndAuthenticate` | `0x00014372` | `SakeClient_DecryptAndValidateServerPermit` | `Sake_Permit_DecryptAndAuthenticate` | Decrypts and validates permit |

### 18.10. Utility

| JNI Function | Address | Internal Call | Java Method | Description |
|:---|:---|:---|:---|:---|
| `AsVoidPtr` | `0x00013f8a` | — | `AsVoidPtr` | Returns pointer as-is (type cast) |
| `cdata` | `0x00013e96` | JNI `NewByteArray` + `GetByteArrayElements` | `cdata` | Copies raw bytes to Java byte array |
| `memmove` | `0x00013efe` | `__aeabi_memmove` | `memmove` | Moves bytes from Java array to native pointer |

### 18.11. Java Class: `NativeSakeLib` (Extracted from `classes.dex`)

```java
package com.medtronic.minimed.sake;

public class NativeSakeLib {
    // Utility
    public static SWIGTYPE_p_void asvoidptr(SWIGTYPE_p_unsigned_char ptr);
    public static byte[] cdata(SWIGTYPE_p_void ptr, int size);
    public static void memmove(SWIGTYPE_p_void dest, byte[] src);

    // Key Database
    public static boolean Sake_KeyDatabase_Open(SAKE_KEY_DATABASE_S db, SWIGTYPE_p_unsigned_char data, long size);

    // Server
    public static boolean Sake_Server_Init(SAKE_SERVER_S server, SAKE_KEY_DATABASE_S db);
    public static void Sake_Server_Destroy(SAKE_SERVER_S server);
    public static SAKE_HANDSHAKE_STATUS_E Sake_Server_Handshake(SAKE_SERVER_S server, SAKE_SECURE_MESSAGE_S input, SAKE_SECURE_MESSAGE_S output);
    public static boolean Sake_Server_SecureForSending(SAKE_SERVER_S server, SAKE_USER_MESSAGE_S userMsg, SAKE_SECURE_MESSAGE_S secureMsg);
    public static boolean Sake_Server_UnsecureAfterReceiving(SAKE_SERVER_S server, SAKE_SECURE_MESSAGE_S secureMsg, SAKE_USER_MESSAGE_S userMsg);
    public static boolean Sake_Server_SetPasskey(SAKE_SERVER_S server, SAKE_SERVER_MEMORY_S memory, SAKE_PASSKEY_S passkey);
}
```

### 18.12. Missing Functions (Not in Binary)

The following functions are referenced in the Java code but NOT present in `libandroid-sake-lib_v210.so`:

*   `Sake_Passkey_FromInteger` — Passkey creation (may be in a different library)
*   `Sake_Server_SetPasskey` — Server passkey setting (may be in a different library)
*   `SAKE_PASSKEY_S` — Passkey struct (not defined in this binary)
*   `SAKE_SERVER_MEMORY_S` — Server memory struct (not defined in this binary)

These may be implemented in a companion library or in a different version of the SAKE library.

---

## 19. JNI Struct Accessors (Complete)

Every JNI getter/setter function has been renamed with descriptive names.

### 19.1. `SAKE_CLIENT_S` Accessors

| JNI Function | Address | Field | Description |
|:---|:---|:---|:---|
| `SakeJNI_Client_SetCurrentState` | `0x00014384` | +0x00 | Sets currentState |
| `SakeJNI_Client_GetCurrentState` | `0x0001439c` | +0x00 | Gets currentState |
| `SakeJNI_Client_SetClientChallenge` | `0x000143b0` | +0x0C | Sets localChallenge[20] |
| `SakeJNI_Client_GetClientChallenge` | `0x000143cc` | +0x0C | Gets localChallenge[20] |
| `SakeJNI_Client_SetServerChallenge` | `0x000143e4` | +0x20 | Sets remoteChallenge[20] |
| `SakeJNI_Client_GetServerChallenge` | `0x00014400` | +0x20 | Gets remoteChallenge[20] |
| `SakeJNI_Client_SetClientIV` | `0x00014418` | +0x0C | Sets client IV |
| `SakeJNI_Client_GetClientIV` | `0x00014430` | +0x0C | Gets client IV |
| `SakeJNI_Client_SetServerIV` | `0x00014444` | +0x20 | Sets server IV |
| `SakeJNI_Client_GetServerIV` | `0x0001445c` | +0x20 | Gets server IV |
| `SakeJNI_Client_SetServerPermit` | `0x0001446e` | +0x1C | Sets serverPermit |
| `SakeJNI_Client_GetServerPermit` | `0x00014488` | +0x1C | Gets serverPermit |
| `SakeJNI_Client_SetServerDeviceType` | `0x00014490` | +0x34 | Sets deviceType |
| `SakeJNI_Client_GetServerDeviceType` | `0x000144a8` | +0x34 | Gets deviceType |
| `SakeJNI_Client_SetKeyDatabase` | `0x000144ba` | +0x38 | Sets keyDatabase |
| `SakeJNI_Client_GetKeyDatabase` | `0x000144c8` | +0x38 | Gets keyDatabase |
| `SakeJNI_Client_SetSecureLink` | `0x000144d0` | +0x40 | Sets secureLink[48] |
| `SakeJNI_Client_GetSecureLink` | `0x00014520` | +0x40 | Gets secureLink[48] |
| `SakeJNI_Client_SetIsSecureLinkEstablished` | `0x00014570` | +0x70 | Sets isSecureLinkEstablished |
| `SakeJNI_Client_GetIsSecureLinkEstablished` | `0x00014580` | +0x70 | Gets isSecureLinkEstablished |
| `SakeJNI_Client_SetLastError` | `0x00014586` | +0x74 | Sets lastError |
| `SakeJNI_Client_GetLastError` | `0x0001458e` | +0x74 | Gets lastError |
| `SakeJNI_AllocClient` | `0x00014592` | — | Allocates 120 bytes |
| `SakeJNI_FreeClient` | `0x000145a2` | — | Frees client struct |

### 19.2. `SAKE_SERVER_S` Accessors

| JNI Function | Address | Field | Description |
|:---|:---|:---|:---|
| `SakeJNI_Server_SetCurrentState` | `0x000145f4` | +0x00 | Sets currentState |
| `SakeJNI_Server_GetCurrentState` | `0x0001460c` | +0x00 | Gets currentState |
| `SakeJNI_Server_SetClientChallenge` | `0x00014620` | +0x04 | Sets localChallenge[20] |
| `SakeJNI_Server_GetClientChallenge` | `0x0001463c` | +0x04 | Gets localChallenge[20] |
| `SakeJNI_Server_SetServerChallenge` | `0x00014654` | +0x18 | Sets remoteChallenge[20] |
| `SakeJNI_Server_GetServerChallenge` | `0x00014670` | +0x18 | Gets remoteChallenge[20] |
| `SakeJNI_Server_SetClientIV` | `0x00014688` | +0x04 | Sets client IV |
| `SakeJNI_Server_GetClientIV` | `0x000146a0` | +0x04 | Gets client IV |
| `SakeJNI_Server_SetServerIV` | `0x000146b4` | +0x18 | Sets server IV |
| `SakeJNI_Server_GetServerIV` | `0x000146cc` | +0x18 | Gets server IV |
| `SakeJNI_Server_SetClientPermit` | `0x000146de` | +0x1C | Sets clientPermit |
| `SakeJNI_Server_GetClientPermit` | `0x000146f8` | +0x1C | Gets clientPermit |
| `SakeJNI_Server_SetClientDeviceType` | `0x00014700` | +0x30 | Sets deviceType |
| `SakeJNI_Server_GetClientDeviceType` | `0x00014718` | +0x30 | Gets deviceType |
| `SakeJNI_Server_SetTemporarySecureLink` | `0x0001472c` | +0x38 | Sets cipherState |
| `SakeJNI_Server_GetTemporarySecureLink` | `0x0001477c` | +0x38 | Gets cipherState |
| `SakeJNI_Server_SetKeyDatabase` | `0x000147cc` | +0x68 | Sets keyDatabase |
| `SakeJNI_Server_GetKeyDatabase` | `0x000147da` | +0x68 | Gets keyDatabase |
| `SakeJNI_Server_SetSecureLink` | `0x000147e4` | +0x70 | Sets secureLink[48] |
| `SakeJNI_Server_GetSecureLink` | `0x00014834` | +0x70 | Gets secureLink[48] |
| `SakeJNI_Server_SetIsSecureLinkEstablished` | `0x00014884` | +0xA0 | Sets isSecureLinkEstablished |
| `SakeJNI_Server_GetIsSecureLinkEstablished` | `0x00014894` | +0xA0 | Gets isSecureLinkEstablished |
| `SakeJNI_Server_SetLastError` | `0x0001489a` | +0xA4 | Sets lastError |
| `SakeJNI_Server_GetLastError` | `0x000148a4` | +0xA4 | Gets lastError |
| `SakeJNI_AllocServer` | `0x000148aa` | — | Allocates 168 bytes |
| `SakeJNI_FreeServer` | `0x000148ba` | — | Frees server struct |

### 19.3. `SAKE_PERMIT_S` Accessors

| JNI Function | Address | Field | Description |
|:---|:---|:---|:---|
| `SakeJNI_Permit_SetVersion` | `0x00014268` | +0x00 | Sets version |
| `SakeJNI_Permit_GetVersion` | `0x00014280` | +0x00 | Gets version |
| `SakeJNI_Permit_SetDeviceType` | `0x00014294` | +0x04 | Sets deviceType |
| `SakeJNI_Permit_GetDeviceType` | `0x000142ac` | +0x04 | Gets deviceType |
| `SakeJNI_Permit_SetProprietaryBytes` | `0x000142be` | +0x08 | Sets proprietaryBytes[10] |
| `SakeJNI_Permit_GetProprietaryBytes` | `0x000142d4` | +0x08 | Gets proprietaryBytes[10] |
| `SakeJNI_Permit_GetProprietaryByteCount` | `0x00014260` | — | Returns constant 10 |

### 19.4. `SAKE_SECURE_MESSAGE_S` Accessors

| JNI Function | Address | Field | Description |
|:---|:---|:---|:---|
| `SakeJNI_SecureMessage_SetBytes` | `0x00014028` | +0x00 | Sets pBytes pointer |
| `SakeJNI_SecureMessage_GetBytes` | `0x0001403a` | +0x00 | Gets pBytes pointer |
| `SakeJNI_SecureMessage_SetByteCount` | `0x00014040` | +0x04 | Sets byteCount |
| `SakeJNI_SecureMessage_GetByteCount` | `0x00014048` | +0x04 | Gets byteCount |
| `SakeJNI_SecureMessage_GetMinByteCount` | `0x0001401c` | — | Returns MIN constant |
| `SakeJNI_SecureMessage_GetMaxByteCount` | `0x00014022` | — | Returns MAX constant |

### 19.5. `SAKE_KEY_DATABASE_S` Accessors

| JNI Function | Address | Field | Description |
|:---|:---|:---|:---|
| `SakeJNI_KeyDatabase_SetBytes` | `0x00014100` | +0x00 | Sets pBytes pointer |
| `SakeJNI_KeyDatabase_GetBytes` | `0x00014108` | +0x00 | Gets pBytes pointer |
| `SakeJNI_KeyDatabase_SetByteCapacity` | `0x0001410e` | +0x04 | Sets byteCapacity |
| `SakeJNI_KeyDatabase_GetByteCapacity` | `0x00014116` | +0x04 | Gets byteCapacity |
| `SakeJNI_KeyDatabase_GetCRCByteCount` | `0x000140e2` | — | Returns CRC byte count |
| `SakeJNI_KeyDatabase_GetDeviceTypeByteCount` | `0x000140e8` | — | Returns device type byte count |
| `SakeJNI_KeyDatabase_GetRemoteDeviceCountByteCount` | `0x000140ee` | — | Returns remote device count byte count |
| `SakeJNI_KeyDatabase_GetHeaderByteCount` | `0x000140f4` | — | Returns header byte count |
| `SakeJNI_KeyDatabase_GetRemoteDeviceKeyCount` | `0x000140fa` | — | Returns remote device key count |

---

## 20. Crypto Helper Functions

| Function | Address | Description |
|:---|:---|:---|
| `SakeCrypto_LookupAlgorithmByID` | `0x00016c90` | Looks up crypto algorithm descriptor by ID from table |
| `SakeCrypto_CleanupCipherContext` | `0x00016d34` | Frees allocated state, calls vtable cleanup, zeroes context |
| `SakeCrypto_InitCipherContext` | `0x00016d70` | Clears context, calls vtable init, sets descriptor pointer |
| `SakeCrypto_ProcessAndVerifyPayload` | `0x00017358` | Processes decrypted payload with cipher, verifies MAC |
| `SakeCrypto_DeriveKeyMaterial` | `0x000173ec` | Derives 16-byte key material using algorithm ID 2 |
| `SakeCrypto_InitCipherAndAllocateState` | `0x00016ffc` | Validates context, allocates 0x24-byte state |
| `SakeCrypto_ProcessCipherBlock` | `0x00016f64` | Processes cipher block, adds output size to written count |
| `SakeCrypto_GetCipherOutputSize` | `0x00016f24` | Returns output size based on algorithm type |
| `SakeCrypto_ValidateCipherContext` | `0x00016e0c` | Validates algorithm type and mode flags |

---

## 21. ARM Unwinding / C++ Runtime Infrastructure

The remaining functions are standard ARM exception handling / C++ runtime infrastructure inserted by the NDK compiler. They are NOT SAKE-specific.

### 21.1. ARM Unwinding Functions

| Function | Address | Description |
|:---|:---|:---|
| `ARM_Unwind_ParseTableEntry` | `0x0001756c` | Parses ARM exception table entry |
| `ARM_Unwind_ProcessInstructions` | `0x000175bc` | Processes ARM exception handling instructions |
| `ARM_Unwind_SetRegister` | `0x00017828` | Sets register value in exception context |
| `ARM_Unwind_GetRegister` | `0x000178d4` | Gets register value from exception context |
| `ARM_Unwind_RestoreRegisters` | `0x00017980` | Restores registers from stack frame |
| `ARM_Unwind_ExecuteFrame` | `0x00017b18` | Executes unwind frame, processes exception handler chain |
| `ARM_Unwind_StepFrame` | `0x00017bb8` | Steps through unwind frame, processes handler chain |
| `ARM_Unwind_ForcedUnwind` | `0x00017cd4` | Performs forced unwinding |
| `ARM_Unwind_GetRegionStart` | `0x00017d3c` | Gets region start address |
| `ARM_Unwind_GetLanguageSpecificData` | `0x00017d70` | Gets language-specific data area pointer |
| `ARM_Unwind_CheckPhase` | `0x00017db0` | Checks unwind phase |
| `ARM_Unwind_SaveCoreRegisters` | `0x00017dc4` | Saves R0-R12, SP, LR to context |
| `ARM_Unwind_SaveVFPRegisters` | `0x00017ddc` | Saves D0-D15 VFP registers |
| `ARM_Unwind_SaveVFPRegisters_D` | `0x00017de4` | Saves D0-D15 VFP registers (variant) |
| `ARM_Unwind_SaveVFPRegisters_D16` | `0x00017dec` | Saves D0-D15 VFP registers (D16 variant) |
| `ARM_Unwind_CopyContext` | `0x00017df4` | Copies unwind context |
| `ARM_Unwind_GetWord` | `0x00017e3c` | Gets word from unwind context |
| `ARM_Unwind_SetWord` | `0x00017e70` | Sets word in unwind context |
| `ARM_Unwind_SetRegPair` | `0x00017eb8` | Sets register pair in unwind context |
| `ARM_Unwind_GetRegPair` | `0x00017ef0` | Gets register pair from unwind context |
| `ARM_Unwind_IsPhase1` | `0x00017f2c` | Checks if in phase 1 unwinding |
| `ARM_Unwind_NextFrame` | `0x00017f32` | Advances to next frame |
| `ARM_Unwind_PopRegisters` | `0x00017f54` | Pops registers from stack |
| `ARM_Unwind_GetCFA` | `0x00017f68` | Gets Canonical Frame Address |
| `ARM_Unwind_SetCFA` | `0x00017f88` | Sets Canonical Frame Address |
| `ARM_Unwind_FlushCache` | `0x00017fa6` | Flushes instruction cache |
| `ARM_Unwind_DecodeULEB128` | `0x00017fe6` | Decodes unsigned LEB128 value |
| `ARM_Unwind_DecodeSLEB128` | `0x00018054` | Decodes signed LEB128 value |
| `ARM_Unwind_ReadHeader` | `0x00018088` | Reads unwind table header |
| `ARM_Unwind_FindFrameInfo` | `0x00018128` | Finds frame info for address |
| `ARM_Unwind_SearchPhase1` | `0x0001819e` | Searches for handler in phase 1 |
| `ARM_Unwind_RaiseException` | `0x00018350` | Raises an exception |
| `ARM_Unwind_Backtrace` | `0x000183b0` | Performs backtrace |
| `ARM_Unwind_ForcedUnwind2` | `0x000183e4` | Performs forced unwinding (variant) |
| `ARM_Unwind_DeleteException` | `0x00018444` | Deletes exception object |
| `ARM_Unwind_Resume` | `0x00018488` | Resumes execution after exception |
| `ARM_Unwind_Resume2` | `0x00018658` | Resumes execution (variant) |

### 21.2. C++ Runtime Functions

| Function | Address | Description |
|:---|:---|:---|
| `ARM_Cxx_CallTerminate` | `0x00018b04` | Calls terminate handler |
| `ARM_Cxx_TerminateHandler` | `0x00018b0c` | Default terminate handler |
| `Stub_NOP` | `0x00013e60` | Empty NOP stub |

---

## 22. Binary Statistics

| Metric | Value |
|:---|:---|
| Total functions | 337 |
| FUN_* remaining | **0** |
| Functions renamed | ~120+ |
| EOL comments added | ~80+ |
| Ghidra structs created | 6 |
| Struct types applied | 25+ functions |
| Sections documented | 22 |
| SAKE-specific functions | ~150 |
| ARM/NDK infrastructure | ~187 |

### 22.1. Coverage Summary

| Subsystem | Status | Functions |
|:---|:---|:---|
| Client Handshake | **100%** | All states, all helpers |
| Server Handshake | **100%** | All states, all helpers |
| AES-128 (ECB/CTR/CMAC) | **100%** | All primitives |
| Key Database | **100%** | Create, open, add, CRC, lookup |
| Permit Subsystem | **100%** | Init, encrypt, decrypt, validate |
| SecureMessage | **100%** | Encrypt, decrypt, MAC, sequence |
| UserMessage | **100%** | Struct, JNI accessors |
| Error Handling | **100%** | Error codes, strings, handlers |
| JNI API Surface | **100%** | All 80+ JNI exports mapped |
| Struct Accessors | **100%** | All getter/setter functions |
| ARM Unwinding | **100%** | All NDK infrastructure renamed |
| Ghidra Datatypes | **100%** | All structs created and applied |

---

## 23. Device Type Table & Enums

### 23.1. Device Type Table

Located at **`0x0001dcf0`** (`SAKE_DEVICE_TYPE_TABLE`), this is an array of 7 pointers to device type name strings:

| Index | Enum Value | String Address | String Value |
|:---|:---|:---|:---|
| 0 | `INSULIN_PUMP` (1) | `0x00019fc0` | `"InsulinPump"` |
| 1 | `GLUCOSE_SENSOR` (2) | `0x00019fcc` | `"GlucoseSensor"` |
| 2 | `BLOOD_GLUCOSE_METER` (3) | `0x00019fda` | `"BloodGlucoseMeter"` |
| 3 | `MOBILE_APPLICATION` (4) | `0x00019fec` | `"MobileApplication"` |
| 4 | `CARELINK_UPLOAD_APPLICATION` (5) | `0x00019ffe` | `"CareLinkUploadApplication"` |
| 5 | `FIRMWARE_UPDATE_APPLICATION` (6) | `0x0001a018` | `"FirmwareUpdateApplication"` |
| 6 | `DIAGNOSTIC_APPLICATION` (7) | `0x0001a032` | `"DiagnosticApplication"` |

**Error string:** `"InvalidDeviceType"` at `0x0001a048`

### 23.2. All Enums (Ghidra-Verified)

| Enum | Size | Values |
|:---|:---|:---|
| `SAKE_CLIENT_STATE_E` | 4 bytes | INIT_OR_RESET=1, EXCHANGE=2, DERIVATION=3, AUTHENTICATION=4, INTERMEDIATE_5=5, CHALLENGE_INIT=6, SESSION_PROOF=7, SUCCESS=8 |
| `SAKE_SERVER_STATE_E` | 4 bytes | INIT_OR_RESET=1, EXCHANGE=2, DERIVE_AND_VERIFY=3, DECRYPT_PERMIT=4, INTERMEDIATE_5=5, FINALIZE=6, INTERMEDIATE_7=7, SUCCESS=8 |
| `SAKE_HANDSHAKE_ERROR_E` | 4 bytes | INVALID=0, NO_ERROR=1, HANDSHAKE_MISUSED=2, SYNC_MESSAGE_INVALID=3, CHALLENGE_GENERATION_FAILED=4, CHALLENGE_INVALID=5, SYNC_RESPONSE_GENERATION_FAILED=6, SYNC_RESPONSE_INVALID=7, REMOTE_DEVICE_TYPE_UNSUPPORTED=8, CHALLENGE_RESPONSE_INVALID=9, CHALLENGE_RESPONSE_GENERATION_FAILED=10, CHALLENGE_RESPONSE_RANDOMIZATION_FAILED=11, SESSION_KEY_DERIVATION_FAILED=12, SESSION_KEY_RANDOMIZATION_FAILED=13, SESSION_KEY_PERMIT_RECEIVE_FAILED=14, PERMIT_SEND_SECURITY_FAILED=15, PERMIT_SEND_PADDING_FAILED=16, PERMIT_RECEIVED_NOT_PADDED=17, PERMIT_RECEIVED_INVALID=18, PERMIT_RECEIVED_DEVICE_TYPE_MISMATCH=19 |
| `SAKE_DEVICE_TYPE_E` | 4 bytes | INSULIN_PUMP=1, GLUCOSE_SENSOR=2, BLOOD_GLUCOSE_METER=3, MOBILE_APPLICATION=4, CARELINK_UPLOAD_APPLICATION=5, FIRMWARE_UPDATE_APPLICATION=6, DIAGNOSTIC_APPLICATION=7 |
| `SAKE_PERMIT_VERSION_E` | 4 bytes | VERSION_1=1, VERSION_2=2, VERSION_3=3 |
| `SAKE_CIPHER_MODE_E` | 4 bytes | DECRYPT=0, ENCRYPT=1 |
| `SAKE_AES_BLOCK_MODE_E` | 4 bytes | ECB_128=128, CBC_128=192, CTR_128=256 |

### 23.3. Enum Application to Struct Fields

| Struct | Field | Enum |
|:---|:---|:---|
| `SAKE_CLIENT_S` | `dwCurrentState` | `SAKE_CLIENT_STATE_E` |
| `SAKE_CLIENT_S` | `dwHandshakeStatus` | `SAKE_HANDSHAKE_ERROR_E` |
| `SAKE_CLIENT_S` | `dwDeviceType` | `SAKE_DEVICE_TYPE_E` |
| `SAKE_SERVER_S` | `dwCurrentState` | `SAKE_SERVER_STATE_E` |
| `SAKE_SERVER_S` | `dwLastError` | `SAKE_HANDSHAKE_ERROR_E` |
| `SAKE_SERVER_S` | `dwDeviceType` | `SAKE_DEVICE_TYPE_E` |
| `SAKE_PERMIT_S` | `dwVersion` | `SAKE_PERMIT_VERSION_E` |
| `SAKE_PERMIT_S` | `dwDeviceType` | `SAKE_DEVICE_TYPE_E` |
| `SAKE_SECURE_LINK_S` | `dwMode` | `SAKE_CIPHER_MODE_E` |

### 23.4. Enum Application to Function Prototypes

| Function | Parameter | Enum |
|:---|:---|:---|
| `SakeClient_HandshakeHandler` | return | `SAKE_HANDSHAKE_ERROR_E` |
| `SakeClient_HandshakeHandler` | statePtr | `SAKE_CLIENT_STATE_E*` |
| `SakeServer_HandshakeHandler` | return | `SAKE_HANDSHAKE_ERROR_E` |
| `SakeServer_HandshakeHandler` | statePtr | `SAKE_SERVER_STATE_E*` |
| `SakeClient_InitChallengeAndSetState` | return | `SAKE_CLIENT_STATE_E` |
| `SakeError_IsValidCode` | errorCode | `SAKE_HANDSHAKE_ERROR_E` |
| `SakeError_GetStringForCode` | errorCode | `SAKE_HANDSHAKE_ERROR_E` |
| `SakeKeyDB_IsValidDeviceType` | deviceType | `SAKE_DEVICE_TYPE_E` |

---
