// RE3R Ultimate Trainer 汉化补丁器
// Strategy: append a UTF-8 string blob after .reloc, redirect every rip-relative
// LEA (and DIR64 data pointer) that targets a translated string to the new blob.
// Original bytes are never overwritten in place.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC_DLL = process.argv[2] || path.join(ROOT, 'dist', 'original_unpacked.dll');
const OUT_DLL = process.argv[3] || path.join(ROOT, 'dist', 're3r_ultimate_trainer_zh.dll');
const REPORT = process.argv[4] || path.join(ROOT, 'dist', 'patch_report.txt');

// ---------- PE helpers ----------
function parsePE(buf) {
  if (buf.readUInt16LE(0) !== 0x5A4D) throw new Error('Not MZ');
  const e_lfanew = buf.readUInt32LE(0x3c);
  if (buf.readUInt32LE(e_lfanew) !== 0x00004550) throw new Error('Not PE');
  const coffOff = e_lfanew + 4;
  const numSections = buf.readUInt16LE(coffOff + 2);
  const sizeOfOptional = buf.readUInt16LE(coffOff + 16);
  const optOff = coffOff + 20;
  const imageBase = buf.readBigUInt64LE(optOff + 24);
  const sectionAlign = buf.readUInt32LE(optOff + 32);
  const fileAlign = buf.readUInt32LE(optOff + 36);
  const sizeOfImage = buf.readUInt32LE(optOff + 56);
  const secOff = optOff + sizeOfOptional;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    sections.push({
      index: i, hdrOff: s,
      name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8), vaddr: buf.readUInt32LE(s + 12),
      rawsize: buf.readUInt32LE(s + 16), rawptr: buf.readUInt32LE(s + 20),
      chars: buf.readUInt32LE(s + 36),
    });
  }
  return { e_lfanew, coffOff, optOff, secOff, numSections, imageBase, sectionAlign, fileAlign, sizeOfImage, sections };
}
const alignUp = (v, a) => Math.ceil(v / a) * a;

// relocations: map file-offset -> reloc type, to identify real 64-bit pointers
function collectRelocSites(buf, pe) {
  // Data directory 5 = BaseRelocationTable
  const ddOff = pe.optOff + 112;
  const relocRva = buf.readUInt32LE(ddOff + 5 * 8);
  const relocSize = buf.readUInt32LE(ddOff + 5 * 8 + 4);
  const sites = new Map(); // file offset -> type
  if (!relocRva) return sites;
  const rvaToOff = rva => {
    for (const s of pe.sections) {
      if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawsize)) {
        const d = rva - s.vaddr;
        return d < s.rawsize ? s.rawptr + d : -1;
      }
    }
    return -1;
  };
  let off = rvaToOff(relocRva);
  const end = off + relocSize;
  while (off >= 0 && off + 8 <= end) {
    const pageRva = buf.readUInt32LE(off);
    const blockSize = buf.readUInt32LE(off + 4);
    if (blockSize === 0) break;
    const nEntries = (blockSize - 8) / 2;
    for (let i = 0; i < nEntries; i++) {
      const e = buf.readUInt16LE(off + 8 + i * 2);
      const type = e >> 12;
      const delta = e & 0xfff;
      if (type === 0) continue; // IMAGE_REL_BASED_ABSOLUTE (padding)
      const targetOff = rvaToOff(pageRva + delta);
      if (targetOff >= 0) sites.set(targetOff, type);
    }
    off += blockSize;
  }
  return sites;
}

// lea scan
function scanLeas(buf, pe) {
  const text = pe.sections.find(s => s.name === '.text');
  const out = [];
  for (let i = text.rawptr; i < text.rawptr + text.rawsize - 7; i++) {
    const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
    if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
      const disp = buf.readInt32LE(i + 3);
      const insnEndVA = pe.imageBase + BigInt(text.vaddr + (i + 7 - text.rawptr));
      const target = insnEndVA + BigInt(disp);
      out.push({ off: i, insnEndVA, target });
      i += 6;
    }
  }
  return out;
}

// literal at VA (for reporting + validation)
function literalAt(buf, pe, va) {
  const rva = Number(va - pe.imageBase);
  for (const s of pe.sections) {
    if (rva >= s.vaddr && rva < s.vaddr + s.vsize) {
      const d = rva - s.vaddr;
      if (d >= s.rawsize) return null;
      let j = s.rawptr + d;
      const end = s.rawptr + s.rawsize;
      let k = j;
      while (k < end && buf[k] !== 0 && k - j < 4000) k++;
      if (k >= end) return null;
      return { off: j, len: k - j, text: buf.slice(j, k).toString('utf8') };
    }
  }
  return null;
}

// ---------- main ----------
const buf = fs.readFileSync(SRC_DLL);
const pe = parsePE(buf);
console.log(`Loaded ${SRC_DLL} (${buf.length} bytes), sections: ${pe.sections.map(s => s.name).join(', ')}`);

// merge translation tables
const tables = ['trans_core.json', 'trans_stages.json', 'trans_items.json'].map(f =>
  JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', f), 'utf8')));
const trans = new Map(); // vaBig -> zh
for (const t of tables) for (const [k, v] of Object.entries(t)) {
  const va = BigInt(k);
  if (trans.has(va)) throw new Error('duplicate VA ' + k);
  trans.set(va, v);
}
console.log('translation entries:', trans.size);

// SSE-loaded strings: patched IN PLACE (utf8 bytes + space pad to original len).
// These strings are read directly from .rdata via movsd/mov/movzx (no lea/pointer).
const sseTable = JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', 'trans_sse.json'), 'utf8'));
const sseEntries = Object.entries(sseTable).map(([k, v]) => ({ va: BigInt(k), zh: v }));
console.log('sse in-place entries:', sseEntries.length);

// validate: each VA must hold an existing literal
for (const [va] of trans) {
  const lit = literalAt(buf, pe, va);
  if (!lit || lit.len === 0) throw new Error('no literal at ' + va.toString(16));
}

// ---------- SSE in-place patches (before anything else) ----------
// Strings constructed via movsd/mov/movzx chunk loads with hardcoded size=len:
// write utf8 bytes, space-pad to exactly len bytes. Byte[len] (NUL) untouched.
const sseSpans = [];
let ssePatched = 0;
for (const { va, zh } of sseEntries) {
  const lit = literalAt(buf, pe, va);
  if (!lit) throw new Error('sse: no literal at 0x' + va.toString(16));
  const nb = Buffer.from(zh, 'utf8');
  if (nb.length > lit.len) {
    throw new Error(`sse: zh too long for 0x${va.toString(16)}: ${nb.length} > ${lit.len} (${JSON.stringify(lit.text)})`);
  }
  if (buf[lit.off + lit.len] !== 0) throw new Error(`sse: byte[len] not NUL at 0x${va.toString(16)}`);
  const padded = Buffer.alloc(lit.len, 0x20);
  nb.copy(padded, 0);
  padded.copy(buf, lit.off);
  sseSpans.push([lit.off, lit.off + lit.len]);
  ssePatched++;
}
console.log('sse in-place patched:', ssePatched);
// dual-reference check: blob entries that also have non-lea rip-rel loads inside them
// (report only; they were moved to the sse table manually)
{
  const textSec0 = pe.sections.find(s => s.name === '.text');
  const nonLeaTargets = new Map();
  for (let off = textSec0.rawptr; off < textSec0.rawptr + textSec0.rawsize - 4; off++) {
    if ((buf[off - 1] & 0xC7) !== 0x05) continue;
    // exclude canonical lea encodings
    const b1 = buf[off - 2], b2 = buf[off - 3];
    if (b1 === 0x8D && (b2 === 0x48 || b2 === 0x4C)) continue;
    const disp = buf.readInt32LE(off);
    if (disp <= -0x30000000 || disp >= 0x30000000) continue;
    const t = Number(pe.imageBase) + textSec0.vaddr + (off + 4 - textSec0.rawptr) + disp;
    if (!nonLeaTargets.has(t)) nonLeaTargets.set(t, 0);
    nonLeaTargets.set(t, nonLeaTargets.get(t) + 1);
  }
  let duals = 0;
  for (const [va] of trans) {
    const lit = literalAt(buf, pe, va);
    for (let d = 0; d < lit.len; d++) {
      if (nonLeaTargets.has(Number(va) + d)) {
        console.log(`WARNING: blob-translated 0x${va.toString(16)} has non-lea rip-ref at +${d}: ${JSON.stringify(lit.text)}`);
        duals++;
        break;
      }
    }
  }
  console.log('dual-referenced blob strings:', duals);
}

// build blob
const reloc = pe.sections.find(s => s.name === '.reloc');
const oldFileSize = buf.length;
const oldRawEnd = reloc.rawptr + reloc.rawsize;
if (oldRawEnd !== oldFileSize) throw new Error(`unexpected file layout: reloc end 0x${oldRawEnd.toString(16)} != file size 0x${oldFileSize.toString(16)}`);
const blobStartDelta = reloc.rawsize; // VA delta from reloc.vaddr to first blob byte

const entries = [...trans.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
const blobParts = [];
const newVA = new Map();
let cursor = 0;
for (const [va, zh] of entries) {
  const bytes = Buffer.from(zh, 'utf8');
  const need = bytes.length + 1;
  blobParts.push(bytes, Buffer.alloc(1)); // string + NUL
  newVA.set(va, pe.imageBase + BigInt(reloc.vaddr + blobStartDelta + cursor));
  cursor += need;
}
const blob = Buffer.concat(blobParts);
console.log(`blob size: ${blob.length} bytes (${entries.length} strings)`);

// write patched file
const out = Buffer.concat([buf, blob]);
const newRawSize = alignUp(reloc.rawsize + blob.length, pe.fileAlign);
const newVSize = alignUp(reloc.rawsize + blob.length, Math.min(pe.sectionAlign, 0x1000));
// section header updates
out.writeUInt32LE(newVSize, reloc.hdrOff + 8);
out.writeUInt32LE(newRawSize, reloc.hdrOff + 16);
// remove discardable flag
out.writeUInt32LE(reloc.chars & ~0x02000000, reloc.hdrOff + 36);
// SizeOfImage
const newSizeOfImage = alignUp(reloc.vaddr + newVSize, pe.sectionAlign);
out.writeUInt32LE(newSizeOfImage, pe.optOff + 56);
console.log(`.reloc: rawsize 0x${reloc.rawsize.toString(16)}->0x${newRawSize.toString(16)}, vsize->0x${newVSize.toString(16)}, SizeOfImage 0x${pe.sizeOfImage.toString(16)}->0x${newSizeOfImage.toString(16)}`);

// redirect lea refs
const leas = scanLeas(out, pe); // scan patched buffer (disp values unchanged so far)
let leaPatched = 0, leaMissed = 0;
const missed = [];
for (const l of leas) {
  if (!newVA.has(l.target)) continue;
  const nv = newVA.get(l.target);
  const disp = Number(nv - l.insnEndVA);
  if (disp < -2147483648 || disp > 2147483647) throw new Error('disp overflow');
  out.writeInt32LE(disp, l.off + 3);
  leaPatched++;
}
// count expected: strings with no lea ref at all
for (const [va] of trans) {
  const has = leas.some(l => l.target === va);
  if (!has) { leaMissed++; missed.push(va); }
}
console.log(`lea refs patched: ${leaPatched}; translated strings with NO lea ref: ${leaMissed}`);
if (missed.length) console.log('  no-ref VAs: ' + missed.map(v => '0x' + v.toString(16)).join(', '));

// redirect DIR64 data pointers
const relocSites = collectRelocSites(out, pe);
const secDataRanges = pe.sections.filter(s => ['.rdata', '.data'].includes(s.name));
let ptrPatched = 0;
for (let i = 0; i + 8 <= out.length; i += 8) {
  const inData = secDataRanges.some(s => i >= s.rawptr && i + 8 <= s.rawptr + s.rawsize);
  if (!inData) continue;
  const q = out.readBigUInt64LE(i);
  if (!newVA.has(q)) continue;
  if (relocSites.get(i) !== 10) continue; // must be a real DIR64-relocated pointer
  out.writeBigUInt64LE(newVA.get(q), i);
  ptrPatched++;
}
console.log('data pointers patched:', ptrPatched);

// checksum (treat odd trailing byte as padded with zero, per PE spec)
out.writeUInt32LE(0, pe.optOff + 64);
let sum = 0;
const csumEnd = out.length % 2 === 0 ? out.length : out.length - 1;
for (let i = 0; i < csumEnd; i += 2) {
  sum += out.readUInt16LE(i);
  sum = (sum & 0xffff) + (sum >>> 16);
}
if (out.length % 2 === 1) sum += out[out.length - 1];
sum = (sum & 0xffff) + (sum >>> 16);
const checksum = (0xffff - sum) & 0xffff;
out.writeUInt32LE(checksum, pe.optOff + 64);

fs.writeFileSync(OUT_DLL, out);
// pad file so size == reloc.rawptr + aligned rawsize (cleaner for loaders)
const padded = Buffer.alloc(reloc.rawptr + newRawSize, 0);
out.copy(padded, 0);
fs.writeFileSync(OUT_DLL, padded);
console.log(`\nwrote ${OUT_DLL} (${padded.length} bytes), checksum 0x${checksum.toString(16)}`);

// ---------- report ----------
const lines = [];
for (const [va, zh] of entries) {
  const lit = literalAt(buf, pe, va); // original literal (from SOURCE buffer)
  const refs = leas.length ? undefined : undefined;
  lines.push(`0x${va.toString(16)}\t${JSON.stringify(lit ? lit.text : '???')}\t->\t${zh}`);
}
lines.push('', `# lea refs patched: ${leaPatched}, strings without lea refs: ${leaMissed}, data pointers patched: ${ptrPatched}`);
fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
console.log('wrote ' + REPORT);
