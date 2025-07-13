# CVE-2016-0058 Analysis 

## Overview

Stack-based buffer overflow in Microsoft’s Windows PDF Library (`PDFLibrary.dll` / `windows.data.pdf.dll`). 

---

## Affected Component

* **DLL**: `PDFLibrary.dll` (invoked by `windows.data.pdf.dll` on Windows 10)
* **Versions**:


  * Patched: Post–MS16‑012 (e.g., **10.0.19041.5794**)

---

## Vulnerability Class

* **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
* **Subtype**: **CWE-121**: Stack-based Buffer Overflow

---

## Unpatched Vulnerable Routines

### 1. FlateDecode Refill (`FUN_100A5XXX`)

```c
// Pseudocode from unpatched binary (RVA 0x100A5XXX)
BYTE localBuf[BUF_SIZE];
BYTE* srcPtr = basePtr + 4;
size_t length = lengthField;  // from PDF /Length
// NO bounds check!
memcpy(localBuf, srcPtr, length);
// ...
memmove(localBuf + length, otherData, length2);
```

### 2. Vector-Grow Helper (`FUN_100C1C65`)

```c
// Unpatched vector-grow
newBuf = allocate(newCapacity);
size_t oldLen = (oldEnd - oldStart) & ~3;
// No check that oldLen <= newCapacity
memmove(newBuf, oldBuf, oldLen);
```

### 3. Tree-Node Copy Helper (`RVA 0x100BA7F6`)

```c
// Unpatched stack-buffer memcpy
if (nodeLen != 0) {
    memcpy(stackBuf, srcData, nodeLen);
}
```

---

## Patched Changes (MS16-012)

Microsoft inserted a 3‑step guard around each raw copy:

1. **Compute** `copyLen`
2. **Validate** `if (copyLen > bufferCapacity) → error`
3. **Copy** only if safe

### Guard Example in FlateDecode Refill (`FUN_18032F80C`)

```c
BYTE* dst = buf;
BYTE* src = dst + 4;
size_t copyLen = endPtr - src;
// Added bounds check
if (copyLen > LOCAL_BUF_SIZE) {
    ThrowPdfException(StreamOverflow);
    return ERROR_OVERFLOW;
}
memmove(dst, src, copyLen);
```

### Guard Example in Vector-Grow (`FUN_100C1C65`)

```c
size_t copyLen = (oldEnd - oldStart) & ~3;
if (copyLen > newCapacity) {
    ThrowPdfException(BufferOverflow);
    return NULL;
}
memmove(newBuf, oldBuf, copyLen);
```

### Guard Example in Tree-Copy Helper

```c
size_t copyLen = nodeLen * sizeof(Element);
if (copyLen > sizeof(stackBuf)) {
    ThrowPdfException(StackOverflow);
    return ERROR_OVERFLOW;
}
memmove(stackBuf, src, copyLen);
```

---

## Residual Risks

1. **Integer Underflow / Overflow**: `endPtr < src` can wrap `copyLen` large enough to bypass `> cap` check.
2. **Boundary Off‑By‑One**: `copyLen == cap` may leave no room for later adjustments (e.g., `endPtr -= 4`).
3. **Incomplete Coverage**: Other filters (ASCIIHex, LZW, etc.) may still contain unchecked copies.
4. **Error-Path Bugs**: Exception handler (`ThrowPdfException`) must fully reset parser state or may leak and crash.
5. **Performance Optimizations**: Future inline or cached checks risk desynchronization and new overflows.

---

## Proof-of-Concept & Debug

* **crash.pdf**: crafted stream with `/Length` >> actual data triggers overflow in unpatched build.
* **WinDbg**: attach to `prevhost.exe` with Microsoft PDF Preview CLSID to hit `FUN_18032F80C`.

---

## Conclusion

The MS16‑012 patch correctly inserts bounds checks, but subtle arithmetic and incomplete filter coverage introduce vulnerabilities. A comprehensive audit and global copy-site hardening (centralized helper) plus targeted fuzzing are recommended to ensure all overflows are eliminated.

---


