// Scan .text for rip-relative LEA instructions targeting string literals.
// Produces: refmap (string VA -> [code sites]), and list of unreferenced strings.
'use strict';
const fs = require('fs');
const path = require('path');

const dllPath = process.argv[2];
const outDir = process.argv[3];
const buf = fs.readFileSync(dllPath);

// --- minimal PE parse ---
function parsePE(buf) {
  if (buf.readUInt16LE(0) !== 0x5A4D) throw new Error('Not MZ');
  const e_lfanew = buf.readUInt32LE(0x3c);
  const coffOff = e_lfanew + 4;
  const numSections = buf.readUInt16LE(coffOff + 2);
  const sizeOfOptional = buf.readUInt16LE(coffOff + 16);
  const optOff = coffOff + 20;
  const magic = buf.readUInt16LE(optOff);
  if (magic !== 0x20b) throw new Error('Not PE32+');
  const imageBase = buf.readBigUInt64LE(optOff + 24);
  const secOff = optOff + sizeOfOptional;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    sections.push({
      name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8),
      vaddr: buf.readUInt32LE(s + 12),
      rawsize: buf.readUInt32LE(s + 16),
      rawptr: buf.readUInt32LE(s + 20),
      chars: buf.readUInt32LE(s + 36),
    });
  }
  return { imageBase, sections, optOff, coffOff, secOff, numSections };
}

const pe = parsePE(buf);
const { imageBase, sections } = pe;

function secOfVA(va) {
  const rva = va - imageBase;
  for (const s of sections) {
    if (rva >= s.vaddr && rva < s.vaddr + s.vsize) return s;
  }
  return null;
}
function offOfVA(va) {
  const s = secOfVA(va);
  if (!s) return -1;
  const delta = Number(va) - imageBase - s.vaddr;
  if (delta >= s.rawsize) return -1; // virtual-only
  return s.rawptr + delta;
}
function vaOfOff(off) {
  for (const s of sections) {
    if (off >= s.rawptr && off < s.rawptr + s.rawsize) {
      return imageBase + BigInt(s.vaddr + (off - s.rawptr));
    }
  }
  return null;
}

// --- collect string literals (NUL-terminated) in .rdata and .data ---
const literals = new Map(); // va (string) -> {off, len, text}
for (const sec of sections) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  let i = sec.rawptr;
  const end = sec.rawptr + sec.rawsize;
  while (i < end) {
    // find NUL-terminated printable run
    let j = i;
    while (j < end && buf[j] >= 0x20 && buf[j] <= 0x7e) j++;
    const len = j - i;
    if (j < end && buf[j] === 0 && len >= 3) {
      const va = imageBase + BigInt(sec.vaddr + (i - sec.rawptr));
      literals.set(va, { off: i, len, text: buf.slice(i, j).toString('ascii'), sec: sec.name });
      i = j + 1;
    } else {
      i = j + 1 > i ? j + 1 : i + 1;
    }
  }
}
console.log('NUL-terminated literals in .rdata/.data:', literals.size);

// --- scan .text for lea r64, [rip+disp32] ---
// 48 8D /r or 4C 8D /r with mod=00 rm=101 ; also 4C/48 with reg field any
const textSec = sections.find(s => s.name === '.text');
const refs = new Map(); // target VA -> array of {off, insnEnd}
let leaCount = 0;
{
  const start = textSec.rawptr;
  const end = textSec.rawptr + textSec.rawsize;
  for (let i = start; i < end - 7; i++) {
    const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
    if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
      const disp = buf.readInt32LE(i + 3);
      const insnEndVA = imageBase + BigInt(textSec.vaddr + (i + 7 - textSec.rawptr));
      const target = insnEndVA + BigInt(disp);
      leaCount++;
      if (!refs.has(target)) refs.set(target, []);
      refs.get(target).push({ off: i, insnEnd: i + 7 });
      i += 6; // skip past disp
    }
  }
}
console.log('rip-relative LEA instructions found in .text:', leaCount);

// stats: how many literals are lea-referenced
let refed = 0;
for (const va of literals.keys()) if (refs.has(va)) refed++;
console.log('literals referenced by LEA:', refed);

// --- save artifacts ---
const litArr = [...literals.entries()].map(([va, v]) => ({ va: '0x' + va.toString(16), ...v, refs: (refs.get(va) || []).length }));
fs.writeFileSync(path.join(outDir, 'literals.json'), JSON.stringify(litArr), 'utf8');

// referenced display-like strings only
function isDisplayLike(t) {
  if (t.length < 4 || t.length > 300) return false;
  if (/^[a-z0-9_\-./\\:<>+~]+$/.test(t)) return false;
  if (t.startsWith('.?A') || t.startsWith('??_')) return false;
  const hasLower = /[a-z]/.test(t);
  const hasUpper = /[A-Z]/.test(t);
  const hasSpace = t.includes(' ');
  if (!hasLower) return false;
  if (!hasUpper && !hasSpace) return false;
  const letters = (t.match(/[A-Za-z]/g) || []).length;
  if (letters / t.length < 0.55) return false;
  return true;
}
const refedDisplay = litArr.filter(l => l.refs > 0 && isDisplayLike(l.text));
fs.writeFileSync(path.join(outDir, 'candidates_referenced.txt'),
  refedDisplay.map(l => `${l.va}\t${l.sec}\trefs=${l.refs}\t${l.text}`).join('\n'), 'utf8');
console.log('referenced display-like candidates:', refedDisplay.length);
