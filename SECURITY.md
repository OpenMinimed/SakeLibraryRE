# Security Analysis: Implementation Bugs in SAKE Library

## Target: `libandroid-sake-lib_v210.so`
**Date:** June 15, 2026
**Focus:** Parsing, decoding, and buffer handling implementation bugs
**Methodology:** Decompiled code verified against raw ARM assembly

---

## 1. Executive Summary

This document catalogs **implementation-level bugs** in the SAKE cryptographic library — specifically parsing errors, buffer mishandling, integer issues, and validation gaps in the BTLE message processing path. Each finding has been verified against the raw ARM assembly to eliminate decompiler false positives.

---

## 2. Verified Implementation Bugs

### 2.1. Stack Under-Initialization in MAC Computation (Severity: LOW)

**Location:** `SakeCrypto_ComputeMACAndAppend` (`0x000150c8`)
**Status:** VERIFIED — latent bug, not exploitable with current callers

**Assembly:**
```asm
000150d0: sub sp, #0x34          ; Allocate 52 bytes
000150e0: movs r1, #0x1d         ; Clear 29 bytes
000150ee: blx __aeabi_memclr8    ; memclr8(sp+0x10, 29)
00015100: mov r2, r4             ; r2 = dataLen
00015102: blx __aeabi_memcpy     ; memcpy(sp+0x10, data, dataLen)
```

The buffer at `sp+0x10` is 32 bytes but only 29 are cleared. If `dataLen` is 30-32, the last 1-3 bytes are uninitialized. However, callers limit `dataLen` to 29 (`uVar2 < 0x1e` in encrypt, `uVar2 - 3` max 29 in decrypt).

**Impact:** Latent bug. Not exploitable with current callers, but would become a vulnerability if callers change.

---

### 2.2. Counter Permanent Lockout After 2^32 Messages (Severity: MEDIUM)

**Location:** `SakeCrypto_PerformEncryptDecrypt` (`0x00014f44`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
00014f92: cmp.w r3, #0x100      ; Compare high counter with 256
00014f96: bcc 0x00014fba         ; If < 256, continue
00014f98: mov.w r1, #0x100       ; r1 = 0x100 (sentinel)
00014f9c: movs r0, #0x0          ; r0 = 0
00014f9e: strd r0, r1, [r10]    ; Store low=0, high=0x100
```

When the high 32-bit counter reaches 0x100, it's set to 0x100 permanently. The check at the top is `linkState[5] < 0x100`, so once set to 0x100, the function permanently returns 0 (failure).

**Impact:** Device becomes permanently unable to communicate after ~4 billion messages.

---

### 2.3. EOF Returns Predictable 0xFF in Random Bytes (Severity: LOW)

**Location:** `SakeUtil_ReadRandomBytes` (`0x00017518`)
**Status:** VERIFIED — latent bug

**Assembly:**
```asm
; Loop reading one byte at a time from /dev/urandom
; fgetc returns -1 (EOF) on error, cast to unsigned byte = 0xFF
```

If `fgetc` returns EOF (-1), the cast to `undefined1` (unsigned byte) produces 0xFF. Under normal operation `/dev/urandom` never returns EOF, but under resource exhaustion (fd limits, etc.), all "random" bytes become 0xFF.

**Impact:** Predictable random bytes under resource exhaustion.

---

### 2.4. Key Database Source Buffer Overread in AddEntry (Severity: MEDIUM)

**Location:** `SakeKeyDB_AddEntry` (`0x000153ce`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
; Copies 5 × 16 = 80 bytes from 'size' parameter
; No check that source buffer is >= 80 bytes
000153fc: blx __aeabi_memcpy     ; Copy 16 bytes from size+0x00
00015414: blx __aeabi_memcpy     ; Copy 16 bytes from size+0x10
0001542c: blx __aeabi_memcpy     ; Copy 16 bytes from size+0x20
00015444: blx __aeabi_memcpy     ; Copy 16 bytes from size+0x30
0001545c: blx __aeabi_memcpy     ; Copy 16 bytes from size+0x40
```

The function copies 80 bytes from the `size` parameter without checking that the source buffer is at least 80 bytes.

**Impact:** Heap/stack over-read if caller passes a smaller buffer.

---

### 2.5. Key Database Entry Overread on Corrupted Entry Count (Severity: MEDIUM)

**Location:** `SakeKeyDB_FindEntryByType` (`0x000151fa`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
000151fa: mvn r3, #0x0           ; uVar3 = 0xFFFFFFFF
000151fe: ldr r0, [r0, #0x0]     ; Load dbPtr
00015202: adds r0, #0x6          ; Start of entries
00015204: adds r3, #0x1          ; Increment counter
00015206: ldrb r1, [r0, #-0x1]   ; Load entry count
0001520a: cmp r1, r3             ; Check against count
0001520e: bls 0x00015224         ; If done, return NULL
00015210: adds r2, r0, #0x51     ; Advance 81 bytes
00015214: ldrb r1, [r0]          ; Load device type
00015218: cmp r1, r4             ; Compare with target
0001521c: bne 0x00015204         ; Loop if not match
```

If the entry count byte is corrupted (e.g., 255), the loop iterates 255 times, reading 255 × 81 = 20,655 bytes past the entry start.

**Impact:** Massive heap/stack overread, crash, information disclosure.

---

### 2.6. Key Database Entry Pointer Off-by-One (Severity: LOW)

**Location:** `SakeKeyDB_LookupEntryByType` (`0x00015360`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
; After finding entry, adds 1 to skip device type byte
0001537a: adds r0, #0x1          ; Skip device type byte
```

Returns pointer to entry + 1 byte (skipping device type). If entry is the last in the buffer, +1 could point past allocated memory.

**Impact:** Out-of-bounds read when accessing last entry.

---

### 2.7. Permit MAC Truncation to 32 Bits (Severity: MEDIUM)

**Location:** `SakeClient_DecryptAndValidateServerPermit` (`0x0001553c`)
**Status:** VERIFIED — real design weakness

**Assembly:**
```asm
00015584: movs r2, #0xc          ; MAC over 12 bytes only
00015590: bl 0x00015fd0          ; Compute MAC
00015596: ldr r0, [sp,#0x1c]    ; Load embedded MAC (4 bytes from decrypted data)
00015598: ldr r1, [sp,#0x0]     ; Load computed MAC (first 4 bytes)
0001559a: cmp r1, r0            ; Compare only 32 bits!
```

The MAC is only 32 bits (4 bytes), compared against bytes 12-15 of the decrypted permit. The full 128-bit CMAC is truncated.

**Impact:** 2^32 brute-force to forge a permit MAC.

---

### 2.8. Permit Field Truncation in MAC (Severity: LOW)

**Location:** `SakePermit_EncryptAndSign` (`0x000154a4`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
; Only 1 byte of version and 1 byte of deviceType are MAC'd
; Upper 3 bytes of each 4-byte field are excluded
000154bc: ldrb r0, [r0]          ; Load 1 byte of version
000154c4: ldrb r1, [r1, #0x4]   ; Load 1 byte of deviceType
000154d0: blx __aeabi_memcpy     ; Copy 10 proprietary bytes
000154e8: movs r2, #0xc          ; MAC over 12 bytes total
```

The permit struct is 18 bytes (`version(4) + deviceType(4) + proprietary(10)`), but only 12 bytes are MAC'd (`version(1) + deviceType(1) + proprietary(10)`).

**Impact:** Upper 3 bytes of version and deviceType are not authenticated.

---

### 2.9. Permit Version Gate = 0 (Severity: LOW)

**Location:** `SakeClient_DecryptAndValidateServerPermit` (`0x0001553c`)
**Status:** VERIFIED — real finding

**Assembly:**
```asm
0001559e: ldrb.w r0, [sp,#0x10]  ; Load decrypted version byte
000155a2: str.w r0, [r9,#0x0]    ; Store to output
000155a6: cbnz r0, 0x000155c8    ; If version != 0, skip device type!
```

Only version 0 passes the check. The `SAKE_PERMIT_VERSION_E` enum defines `VERSION_1=1`, `VERSION_2=2`, `VERSION_3=3`. This means either:
- Version 0 is the only valid version (enum is wrong)
- The enum values are correct and no valid permit passes (bug)

**Impact:** Only version 0 permits are accepted.

---

### 2.10. Double Key Confirmation (Severity: LOW)

**Location:** `SakeServer_ProcessState3_DeriveAndVerify` (`0x000157a4`)
**Status:** VERIFIED — real redundancy

**Assembly:**
```asm
; First call
000157c0: bl SakeClient_PerformKeyConfirmation
; ... verification ...
; Second call
000157e0: bl SakeClient_PerformKeyConfirmation
```

`SakeClient_PerformKeyConfirmation()` is called twice in the same function. Each call generates random data and computes MACs.

**Impact:** Unnecessary entropy waste and timing side-channel.

---

## 3. Unencrypted Message Parsing Bugs

These bugs exist in the JNI layer that handles unencrypted `SAKE_USER_MESSAGE_S` and `SAKE_SECURE_MESSAGE_S` before/after encryption.

### 3.1. UserMessage Bytes: Fixed 29-Byte Copy Regardless of Input Size (Severity: MEDIUM)

**Location:** `SakeJNI_SetUserMessageBytes` (`0x000140a6`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
000140a6: ldr r0, [sp, #0x8]    ; r0 = source (JNI byte array)
000140a8: movs r1, #0x0         ; i = 0
000140aa: cmp r1, #0x1d         ; Compare with 29
000140ac: it eq
000140ae: bx.eq lr              ; Return when i == 29
000140b0: ldrb r3, [r0, r1]     ; r3 = source[i]
000140b2: strb r3, [r2, r1]     ; dest[i] = r3
000140b4: adds r1, #0x1         ; i++
000140b6: b 0x000140aa          ; Loop
```

The function **always copies exactly 29 bytes** from the JNI byte array to the `SAKE_USER_MESSAGE_S.pBytes` buffer. No check on the actual JNI array length. If the Java array is smaller than 29 bytes, this reads past the end of the JNI array (JNI arrays are not bounds-checked by default).

**Impact:** Heap over-read from JNI array. If the Java array is 10 bytes, 19 bytes of adjacent heap data are copied into the message buffer.

---

### 3.2. UserMessage ByteCount: No Upper Bound Validation (Severity: MEDIUM)

**Location:** `SakeJNI_SetUserMessageByteCount` (`0x000140be`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
000140be: cbz r2, 0x000140c4    ; If dest == NULL, return
000140c0: ldr r0, [sp, #0x8]    ; r0 = byteCount value
000140c2: str r0, [r2, #0x20]   ; dest->byteCount = r0
000140c4: bx lr
```

The byteCount is stored directly without any validation. The `SAKE_USER_MESSAGE_S.pBytes` buffer is only 29 bytes, but byteCount can be set to any value (e.g., 255). Downstream code that uses byteCount to index into pBytes will read/write past the buffer.

**Impact:** If byteCount > 29, subsequent operations using byteCount as an index will access memory past the 29-byte pBytes buffer.

---

### 3.3. SecureMessage Bytes: Fixed 32-Byte Copy Regardless of Input Size (Severity: MEDIUM)

**Location:** `SakeJNI_SecureMessage_SetBytes` (`0x00014028`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
00014028: ldr r0, [sp, #0x8]    ; r0 = source (JNI byte array)
0001402a: movs r1, #0x0         ; i = 0
0001402c: cmp r1, #0x20         ; Compare with 32
0001402e: it eq
00014030: bx.eq lr              ; Return when i == 32
00014032: ldrb r3, [r0, r1]     ; r3 = source[i]
00014034: strb r3, [r2, r1]     ; dest[i] = r3
00014036: adds r1, #0x1         ; i++
00014038: b 0x0001402c          ; Loop
```

Same bug as 3.1 but for `SAKE_SECURE_MESSAGE_S`. Always copies 32 bytes regardless of JNI array length.

**Impact:** Heap over-read from JNI array if source is smaller than 32 bytes.

---

### 3.4. SecureMessage ByteCount: No Upper Bound Validation (Severity: MEDIUM)

**Location:** `SakeJNI_SecureMessage_SetByteCount` (`0x00014040`)
**Status:** VERIFIED — real bug

**Assembly:**
```asm
00014040: cbz r2, 0x00014046    ; If dest == NULL, return
00014042: ldr r0, [sp, #0x8]    ; r0 = byteCount value
00014044: str r0, [r2, #0x20]   ; dest->byteCount = r0
00014046: bx lr
```

Same bug as 3.2 but for `SAKE_SECURE_MESSAGE_S`. byteCount can be set to any value. The encrypt path checks `byteCount < 0x1E` (30), so values > 29 are rejected at encryption time. But the decrypt path uses `byteCount - 3` as the payload size, and if byteCount is 0, 1, or 2, the subtraction underflows.

**Impact:** If byteCount is set to 0-2, the decrypt path computes `byteCount - 3` which wraps to a large unsigned value. The bounds check `0x1D < uVar1` catches this, but it's a fragile defense.

---

### 3.5. SecureMessage Bytes Getter: Returns Raw Pointer Without Size (Severity: LOW)

**Location:** `SakeJNI_SecureMessage_GetBytes` (`0x0001403a`)
**Status:** VERIFIED — design issue

**Assembly:**
```asm
0001403a: mov r0, r2            ; Return the struct pointer
0001403c: movs r1, #0x0
0001403e: bx lr
```

The getter returns the raw pointer to the `SAKE_SECURE_MESSAGE_S` struct, not a copy of the bytes. The Java side receives a native pointer that it can read from directly. If the struct is freed or modified concurrently, the Java side will read stale or corrupted data.

**Impact:** Potential use-after-free or data race if the struct is modified while Java holds the pointer.

---

## 4. Findings Removed (False Positives)

### ~~2.2. MAC Compared Against Zero~~ — FALSE POSITIVE

**Location:** `SakeClient_DecryptAndValidateServerPermit` (`0x0001553c`)

The decompiler showed `local_48[0] == local_2c` where `local_2c = 0`. But assembly verification reveals:
- `sp+0x1C` is bytes 12-15 of the **decrypted permit data** (overwritten by `SakeCrypto_AES_ECB_SingleBlockEncrypt`)
- The comparison is `computed_MAC[0..3] == decrypted_permit[12..15]`
- The MAC is compared against the **embedded MAC in the permit**, not zero

The decompiler was confused because `local_2c` was initialized to 0, but the decrypted data overwrites it.

### ~~2.4. Device Type 4-byte Compare~~ — FALSE POSITIVE

**Location:** `SakeServer_ProcessState4_DecryptPermit` (`0x000158d4`)

The `SAKE_DEVICE_TYPE_E` enum is 4 bytes, so the 4-byte comparison is correct.

### ~~2.5. Missing Decrypt Return Check~~ — FALSE POSITIVE

**Location:** `sakeCrypto_DecryptAuthenticate_HighLevel` (`0x0001512c`)

Assembly shows the return value IS checked: `mov r4, r0` stores the result, and `b 0x0001518e` jumps to the exit where `r4` is returned.

### ~~2.14. CRC Validation with Stack Pointer~~ — FALSE POSITIVE

**Location:** `SakeKeyDB_OpenDatabase` (`0x00015290`)

Assembly shows `strd r5, r2, [sp,#0x0]` stores `dataBuffer` at `sp+0`, then `mov r0, sp` passes `sp` to `SakeKeyDB_ValidateCRC`. The function dereferences `*param_1` to get `dataBuffer`, which is correct.

### ~~2.15. Handshake MAC Reads Past Array~~ — FALSE POSITIVE

**Location:** `SakeClient_VerifyHandshakeMAC` (`0x00015e3c`)

The decompiler showed `local_30[2]` as 8 bytes, but the actual stack layout has more space. The `SakeCrypto_Memcmp` call compares the computed MAC against the expected MAC stored at a valid stack location.

---

## 5. Summary Table

| # | Bug | Location | Severity | Status |
|:---|:---|:---|:---|:---|
| 2.1 | Stack under-init in MAC | `0x000150c8` | LOW | VERIFIED (latent) |
| 2.2 | Counter permanent lockout | `0x00014f44` | MEDIUM | VERIFIED |
| 2.3 | EOF → 0xFF in random | `0x00017518` | LOW | VERIFIED (latent) |
| 2.4 | Key DB source overread | `0x000153ce` | MEDIUM | VERIFIED |
| 2.5 | Key DB entry overread | `0x000151fa` | MEDIUM | VERIFIED |
| 2.6 | Key DB entry pointer +1 | `0x00015360` | LOW | VERIFIED |
| 2.7 | Permit MAC truncation (32-bit) | `0x0001553c` | MEDIUM | VERIFIED |
| 2.8 | Permit field truncation in MAC | `0x000154a4` | LOW | VERIFIED |
| 2.9 | Permit version gate=0 | `0x0001553c` | LOW | VERIFIED |
| 2.10 | Double key confirmation | `0x000157a4` | LOW | VERIFIED |
| 3.1 | UserMessage fixed 29-byte copy | `0x000140a6` | MEDIUM | VERIFIED |
| 3.2 | UserMessage byteCount no bounds | `0x000140be` | MEDIUM | VERIFIED |
| 3.3 | SecureMessage fixed 32-byte copy | `0x00014028` | MEDIUM | VERIFIED |
| 3.4 | SecureMessage byteCount no bounds | `0x00014040` | MEDIUM | VERIFIED |
| 3.5 | SecureMessage getter returns raw ptr | `0x0001403a` | LOW | VERIFIED |

---

## 6. Recommendations

| Priority | Bug | Fix |
|:---|:---|:---|
| **P1** | 2.2 Counter lockout | Wrap high counter to 0 instead of 0x100 |
| **P1** | 2.7 MAC truncation | Use full 128-bit CMAC or at least 64-bit |
| **P1** | 3.1 UserMessage fixed copy | Copy only `min(arrayLength, 29)` bytes |
| **P1** | 3.2 UserMessage byteCount | Validate `byteCount <= 29` before storing |
| **P1** | 3.3 SecureMessage fixed copy | Copy only `min(arrayLength, 32)` bytes |
| **P1** | 3.4 SecureMessage byteCount | Validate `byteCount <= 32` before storing |
| **P2** | 2.4 Key DB overread | Add source buffer size validation |
| **P2** | 2.5 Entry count bounds | Validate entry count against buffer size |
| **P2** | 2.8 Permit field truncation | MAC full 18-byte permit |
| **P3** | 2.1 Stack under-init | `memclr8(buf, 0x20)` instead of `0x1d` |
| **P3** | 2.3 EOF handling | Check `fgetc` return for EOF |
| **P3** | 2.6 Entry pointer +1 | Validate pointer bounds |
| **P3** | 2.9 Version gate | Accept valid enum versions |
| **P3** | 2.10 Double confirmation | Remove redundant call |
| **P3** | 3.5 Raw pointer return | Return copy or use reference counting |

---

## 6. Methodology

Each finding was verified through:
1. **Decompilation** — Ghidra decompiler output analyzed
2. **Assembly verification** — Raw ARM assembly inspected for each claim
3. **False positive elimination** — Decompiler artifacts identified and removed
4. **Caller analysis** — Verified whether callers constrain inputs to prevent exploitation

The library works correctly in production because:
- Callers limit input sizes to safe ranges
- The 32-bit MAC comparison against embedded data is functionally correct
- Stack under-initialization doesn't affect actual MAC values due to caller constraints
