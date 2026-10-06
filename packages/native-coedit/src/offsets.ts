// UTF-8 byte ⇄ UTF-16 code-unit index conversion.
//
// Every coedit boundary (wire offsets, Yjs positions surfaced to the app)
// is denominated in UTF-8 BYTES, while JS strings are UTF-16. These helpers
// convert at the edge so the client core never mixes the two.
//
// Semantics:
// - Offsets are clamped into range ([0, byteLength] / [0, text.length]).
// - A byte offset landing *inside* a multi-byte sequence floors to the
//   UTF-16 index of the code point containing it.
// - A UTF-16 offset landing *inside* a surrogate pair floors to the byte
//   offset of that pair's first byte.
// - Lone surrogates encode as U+FFFD (3 bytes), matching TextEncoder, so a
//   string containing them converts exactly as TextEncoder would encode it.

const encoder = new TextEncoder();

function utf16CharLength(text: string, index: number): number {
  const cp = text.codePointAt(index) as number;
  return cp > 0xffff ? 2 : 1;
}

function charByteLength(text: string, index: number, charLen: number): number {
  return encoder.encode(text.slice(index, index + charLen)).length;
}

/** UTF-8 byte offset → UTF-16 code-unit index. */
export function utf8OffsetToUtf16(text: string, byteOffset: number): number {
  const totalBytes = encoder.encode(text).length;
  const target = Math.max(0, Math.min(totalBytes, Math.trunc(byteOffset)));
  let bytes = 0;
  let i = 0;
  while (i < text.length) {
    const charLen = utf16CharLength(text, i);
    const charBytes = charByteLength(text, i, charLen);
    if (bytes + charBytes > target) break;
    bytes += charBytes;
    i += charLen;
  }
  return i;
}

/** UTF-16 code-unit index → UTF-8 byte offset. */
export function utf16OffsetToUtf8(text: string, utf16Offset: number): number {
  const target = Math.max(0, Math.min(text.length, Math.trunc(utf16Offset)));
  let bytes = 0;
  let i = 0;
  while (i < text.length) {
    const charLen = utf16CharLength(text, i);
    if (i + charLen > target) break;
    bytes += charByteLength(text, i, charLen);
    i += charLen;
  }
  return bytes;
}

/** UTF-8 byte length of a string (what the wire counts). */
export function utf8Length(text: string): number {
  return encoder.encode(text).length;
}
