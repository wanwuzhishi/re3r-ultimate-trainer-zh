// Complete inventory for the trainer string region:
// - all literals with LEA refs
// - all literals referenced via 8-byte data pointers (char* arrays)
'use strict';
const fs = require('fs');
const path = require('path');
const dllPath = process.argv[2];
const outDir = process.argv[3];
const buf = fs.readFileSync(dllPath);

function parsePE(buf) {
  const e_lfanew = buf.readUInt32LE(0x3c);
  const coffOff = e_lfanew + 4;
  const numSections = buf.readUInt16LE(coffOff + 2);
  const sizeOfOptional = buf.readUInt16LE(coffOff + 16);
  const optOff = coffOff + 20;
  const imageBase = buf.readBigUInt64LE(optOff + 24);
  const secOff = optOff + sizeOfOptional;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    sections.push({
      name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8), vaddr: buf.readUInt32LE(s + 12),
      rawsize: buf.readUInt32LE(s + 16), rawptr: buf.readUInt32LE(s + 20),
      chars: buf.readUInt32LE(s + 36),
    });
  }
  return { imageBase, sections };
}
const pe = parsePE(buf);
const { imageBase, sections } = pe;
const secOfVA = va => {
  const rva = va - imageBase;
  for (const s of sections) if (rva >= s.vaddr && rva < s.vaddr + s.vsize) return s;
  return null;
};
const offOfVA = va => {
  const s = secOfVA(va);
  if (!s) return -1;
  const d = Number(va - imageBase) - s.vaddr;
  return d >= 0 && d < s.rawsize ? s.rawptr + d : -1;
};

// literals in .rdata/.data
const literals = new Map();
for (const sec of sections) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  let i = sec.rawptr;
  const end = sec.rawptr + sec.rawsize;
  while (i < end) {
    let j = i;
    while (j < end && buf[j] >= 0x20 && buf[j] <= 0x7e) j++;
    const len = j - i;
    if (j < end && buf[j] === 0 && len >= 2) {
      const va = imageBase + BigInt(sec.vaddr + (i - sec.rawptr));
      literals.set(va, { off: i, len, text: buf.slice(i, j).toString('ascii') });
      i = j + 1;
    } else i = (j > i ? j : i + 1);
  }
}
// lea refs
const textSec = sections.find(s => s.name === '.text');
const leaRefs = new Map();
for (let i = textSec.rawptr; i < textSec.rawptr + textSec.rawsize - 7; i++) {
  const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
  if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
    const disp = buf.readInt32LE(i + 3);
    const target = imageBase + BigInt(textSec.vaddr + (i + 7 - textSec.rawptr)) + BigInt(disp);
    if (!leaRefs.has(target)) leaRefs.set(target, []);
    leaRefs.get(target).push(i);
    i += 6;
  }
}
// data pointer refs in .rdata/.data (8-aligned QW == literal VA)
const ptrRefs = new Map();
for (const sec of sections) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  const start = sec.rawptr, end = sec.rawptr + sec.rawsize;
  for (let o = start; o + 8 <= end; o += 8) {
    const q = buf.readBigUInt64LE(o);
    if (q >= imageBase && q < imageBase + 0x10000000n) {
      if (literals.has(q)) {
        if (!ptrRefs.has(q)) ptrRefs.set(q, []);
        ptrRefs.get(q).push(o);
      }
    }
  }
}

const LO = 0x1803d2f00n, HI = 0x180480000n;
const rows = [];
for (const [va, lit] of literals) {
  if (va < LO || va >= HI) continue;
  const lr = (leaRefs.get(va) || []).length;
  const pr = (ptrRefs.get(va) || []).length;
  if (lr + pr > 0) rows.push({ va, text: lit.text, len: lit.len, lr, pr });
}
rows.sort((a, b) => (a.va < b.va ? -1 : 1));
fs.writeFileSync(path.join(outDir, 'inventory.txt'),
  rows.map(r => `0x${r.va.toString(16)}\tlen=${r.len}\tlea=${r.lr}\tptr=${r.pr}\t${r.text}`).join('\n'), 'utf8');
console.log('inventory rows:', rows.length);
const noLea = rows.filter(r => r.lr === 0);
console.log('rows with ptr refs only:', noLea.length);
fs.writeFileSync(path.join(outDir, 'ptr_only.txt'),
  noLea.map(r => `0x${r.va.toString(16)}\tlen=${r.len}\tlea=0\tptr=${r.pr}\t${r.text}`).join('\n'), 'utf8');
