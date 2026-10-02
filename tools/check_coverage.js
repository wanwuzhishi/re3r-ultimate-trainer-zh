// Completeness check: which display-like, lea-referenced literals in the trainer
// regions are NOT covered by the translation tables?
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');
const buf = fs.readFileSync(path.join(ROOT, 'out', 're3r_ultimate_trainer_unpacked.dll'));

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
    });
  }
  return { imageBase, sections };
}
const pe = parsePE(buf);
const isStrChar = c => (c >= 0x20 && c <= 0x7e) || c === 0x0a || c === 0x0d || c === 0x09;

const literals = new Map();
for (const sec of pe.sections) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  let i = sec.rawptr;
  const end = sec.rawptr + sec.rawsize;
  while (i < end) {
    let j = i;
    while (j < end && isStrChar(buf[j])) j++;
    const len = j - i;
    if (j < end && buf[j] === 0 && len >= 2) {
      const va = pe.imageBase + BigInt(sec.vaddr + (i - sec.rawptr));
      literals.set(va, buf.slice(i, j).toString('ascii'));
      i = j + 1;
    } else i = (j > i ? j : i + 1);
  }
}
const text = pe.sections.find(s => s.name === '.text');
const leaRefs = new Map();
for (let i = text.rawptr; i < text.rawptr + text.rawsize - 7; i++) {
  const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
  if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
    const disp = buf.readInt32LE(i + 3);
    const target = pe.imageBase + BigInt(text.vaddr + (i + 7 - text.rawptr)) + BigInt(disp);
    leaRefs.set(target, (leaRefs.get(target) || 0) + 1);
    i += 6;
  }
}

const trans = new Map();
for (const f of ['trans_core.json', 'trans_stages.json', 'trans_items.json'])
  for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(path.join(ROOT, f), 'utf8'))))
    trans.set(BigInt(k), v);

const RANGES = [[0x1803d2f00n, 0x1803da300n], [0x1803dbd80n, 0x1803e3900n], [0x18047c000n, 0x18047d000n], [0x18060e000n, 0x18060e100n]];
const skip = [
  /^[a-z0-9_\-./\\:<>+~]+$/,          // snake_case/ids/paths
  /^\.\?/, /^\?\?_/,                   // RTTI
  /^[A-Z][a-zA-Z0-9]*$/,               // single CamelCase word (ids like TitleWindow)
  /^[A-Z][a-zA-Z0-9]*(Tip|Toast\w*|Label|Btn\w*|Header|Title|Cmd|Widget)$/,
  /^[A-Z]{2,}[0-9a-zA-Z]*$/,           // AF, HOTKEY, NoAction
  /^(BT\.709|FXAA\+TAA|TAA|Sparda|SSSrank|DDDRank|Nero|Dante|Vergil|Dante & Vergil|N\/A| N\/A| by |by |2023|2\. 0\. 3|Raz0r|HUNK)$/,
  /SaveFile::|MIDHOOK|SceneManager (write|read)|Hook Conflict Handler|SceneManager as Dependency|^HOOK \{/,
  /^[0-9.]+$|^[0-9a-f_]+$/,
];
let missing = [];
for (const [lo, hi] of RANGES) {
  for (const [va, text] of literals) {
    if (va < lo || va >= hi) continue;
    if (trans.has(va)) continue;
    if (!(leaRefs.get(va) > 0)) continue;
    if (skip.some(re => re.test(text))) continue;
    if (!/[a-zA-Z]/.test(text)) continue;
    missing.push(`0x${va.toString(16)}\t${JSON.stringify(text)}`);
  }
}
console.log('possibly-missed display strings:', missing.length);
for (const m of missing) console.log(' ', m);
