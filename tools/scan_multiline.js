// Re-extract literals INCLUDING \n\r\t (multi-line strings), re-scan lea refs,
// and dump the trainer-region literals (display candidates) with newlines visible.
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

const isStrChar = c => (c >= 0x20 && c <= 0x7e) || c === 0x0a || c === 0x0d || c === 0x09;

const literals = new Map();
for (const sec of sections) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  let i = sec.rawptr;
  const end = sec.rawptr + sec.rawsize;
  while (i < end) {
    let j = i;
    while (j < end && isStrChar(buf[j])) j++;
    const len = j - i;
    if (j < end && buf[j] === 0 && len >= 2 && buf.slice(i, j).includes(0x0a)) {
      // only record NEW multiline strings (with newlines); single-line ones already known
      const va = imageBase + BigInt(sec.vaddr + (i - sec.rawptr));
      literals.set(va, { off: i, len, text: buf.slice(i, j).toString('ascii') });
      i = j + 1;
    } else i = (j > i ? j : i + 1);
  }
}
console.log('multi-line literals found:', literals.size);

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
let refed = 0;
const rows = [];
for (const [va, lit] of literals) {
  const n = (leaRefs.get(va) || []).length;
  if (n > 0) { refed++; rows.push({ va, text: lit.text, refs: n }); }
}
console.log('referenced multi-line literals:', refed);
rows.sort((a, b) => (a.va < b.va ? -1 : 1));
// dump all (not only trainer range) since multiline texts may sit anywhere
fs.writeFileSync(path.join(outDir, 'multiline.txt'),
  rows.map(r => `0x${r.va.toString(16)}\trefs=${r.refs}\t${JSON.stringify(r.text)}`).join('\n'), 'utf8');
console.log('wrote multiline.txt');
