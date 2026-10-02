// Find ALL strings referenced via non-LEA rip-relative loads (SSE/mov/movzx),
// i.e. strings missed by the lea-based pipeline. Report:
//  A) string starts with 0 lea refs (pure SSE-loaded strings)
//  B) rip-rel targets INSIDE strings (continuation loads)
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');
const buf = fs.readFileSync(path.join(ROOT, 'out', 're3r_ultimate_trainer_unpacked.dll'));

const e = buf.readUInt32LE(0x3c), coff = e + 4, opt = coff + 20;
const nSec = buf.readUInt16LE(coff + 2), szOpt = buf.readUInt16LE(coff + 16), secOff = opt + szOpt;
const ib = buf.readBigUInt64LE(opt + 24);
const secs = [];
for (let i = 0; i < nSec; i++) {
  const s = secOff + i * 40;
  secs.push({ name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
    vsize: buf.readUInt32LE(s + 8), vaddr: buf.readUInt32LE(s + 12),
    rawsize: buf.readUInt32LE(s + 16), rawptr: buf.readUInt32LE(s + 20) });
}
const rvaToSec = rva => secs.find(s => rva >= s.vaddr && rva < s.vaddr + s.vsize);

// literals
const isStrChar = c => (c >= 0x20 && c <= 0x7e) || c === 0x0a || c === 0x0d || c === 0x09;
const litByVA = new Map(); // va -> {off, len, text, sec}
const litAt = new Map();   // file off -> va (string start)
const litCover = new Map(); // file off -> va (string covering this offset)
for (const sec of secs) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  let i = sec.rawptr;
  const end = sec.rawptr + sec.rawsize;
  while (i < end) {
    let j = i;
    while (j < end && isStrChar(buf[j])) j++;
    const len = j - i;
    if (j < end && buf[j] === 0 && len >= 2) {
      const va = ib + BigInt(sec.vaddr + (i - sec.rawptr));
      const rec = { off: i, len, text: buf.slice(i, j).toString('ascii'), sec: sec.name };
      litByVA.set(va, rec);
      for (let k = i; k < j; k++) litCover.set(k, va);
      litAt.set(i, va);
      i = j + 1;
    } else i = (j > i ? j : i + 1);
  }
}
// lea refs
const text = secs.find(s => s.name === '.text');
const leaRefs = new Map();
for (let i = text.rawptr; i < text.rawptr + text.rawsize - 7; i++) {
  const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
  if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
    const disp = buf.readInt32LE(i + 3);
    const target = ib + BigInt(text.vaddr + (i + 7 - text.rawptr)) + BigInt(disp);
    leaRefs.set(target, (leaRefs.get(target) || 0) + 1);
    i += 6;
  }
}
// ALL rip-relative targets (every dword window)
const va2off = va => {
  const rva = Number(va - ib);
  for (const s of secs) {
    if (rva >= s.vaddr && rva < s.vaddr + s.vsize) {
      const d = rva - s.vaddr;
      return d < s.rawsize ? s.rawptr + d : -1;
    }
  }
  return -1;
};
const sseStart = new Map();  // va -> [sites] (string starts with 0 lea refs)
const sseInside = new Map(); // va -> {inner:[offs], sites:[...]}
for (let off = text.rawptr; off < text.rawptr + text.rawsize - 4; off++) {
  // validate: preceding byte must be a ModRM with mod=00,rm=101 (rip-relative operand)
  if ((buf[off - 1] & 0xC7) !== 0x05) continue;
  const disp = buf.readInt32LE(off);
  if (disp > -0x30000000 && disp < 0x30000000) {
    const tNum = Number(ib) + text.vaddr + (off + 4 - text.rawptr) + disp;
    const t = BigInt(tNum);
    const tOff = va2off(t);
    if (tOff < 0) continue;
    const cv = litCover.get(tOff);
    if (cv === undefined) continue;
    const lit = litByVA.get(cv);
    const isStart = litAt.get(tOff) === t;
    if (isStart) {
      if (!(leaRefs.get(t) > 0)) {
        if (!sseStart.has(t)) sseStart.set(t, []);
        sseStart.get(t).push(off);
      }
    } else {
      // target inside a string; if the string itself has no lea refs at all, it's an SSE continuation
      if (!(leaRefs.get(cv) > 0)) {
        if (!sseInside.has(cv)) sseInside.set(cv, { inner: [], sites: [] });
        sseInside.get(cv).inner.push(tNum - Number(cv));
        sseInside.get(cv).sites.push(off);
      }
    }
  }
}
// merge: SSE strings = starts ∪ continuations
const rows = [];
for (const [va, sites] of sseStart) {
  const lit = litByVA.get(va);
  rows.push({ va: '0x' + va.toString(16), len: lit.len, refs: sites.length, text: lit.text });
}
for (const [va, info] of sseInside) {
  if (sseStart.has(va)) continue;
  const lit = litByVA.get(va);
  rows.push({ va: '0x' + va.toString(16), len: lit.len, refs: info.sites.length, text: lit.text + '   [inside-loads at +' + info.inner.join(',+') + ']' });
}
rows.sort((a, b) => BigInt(a.va) < BigInt(b.va) ? -1 : 1);
fs.writeFileSync(path.join(ROOT, 'out2', 'sse_strings.txt'),
  rows.map(r => `${r.va}\tlen=${r.len}\tloads=${r.refs}\t${JSON.stringify(r.text)}`).join('\n'), 'utf8');
console.log('SSE-loaded strings (no lea refs at all):', rows.length);
