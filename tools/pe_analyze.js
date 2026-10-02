// PE analyzer: dump headers, sections, exports, and ASCII strings with VAs.
// Pure Node, no dependencies.
'use strict';
const fs = require('fs');
const path = require('path');

const dllPath = process.argv[2] || 'F:/RE3RUTrainerByRaz0r-9-2-0-3-1702899673/reframework/plugins/re3r_ultimate_trainer.dll';
const outDir = process.argv[3] || path.join(__dirname, '..', 'out');
fs.mkdirSync(outDir, { recursive: true });

const buf = fs.readFileSync(dllPath);

// --- DOS header ---
if (buf.readUInt16LE(0) !== 0x5A4D) throw new Error('Not MZ');
const e_lfanew = buf.readUInt32LE(0x3c);
if (buf.readUInt32LE(e_lfanew) !== 0x00004550) throw new Error('Not PE');

const coffOff = e_lfanew + 4;
const machine = buf.readUInt16LE(coffOff);
const numSections = buf.readUInt16LE(coffOff + 2);
const sizeOfOptional = buf.readUInt16LE(coffOff + 16);
const optOff = coffOff + 20;
const magic = buf.readUInt16LE(optOff);
if (magic !== 0x20b) throw new Error('Not PE32+ (x64)');

const imageBase = buf.readBigUInt64LE(optOff + 24);
const sizeOfHeaders = buf.readUInt32LE(optOff + 60);
const checksum = buf.readUInt32LE(optOff + 64);
const subsystem = buf.readUInt16LE(optOff + 68);
const numberOfRvaAndSizes = buf.readUInt32LE(optOff + 108);

console.log(`Machine: 0x${machine.toString(16)} (0x8664=x64)`);
console.log(`ImageBase: 0x${imageBase.toString(16)}`);
console.log(`SizeOfHeaders: 0x${sizeOfHeaders.toString(16)}, Checksum: 0x${checksum.toString(16)}, Subsystem: ${subsystem}`);
console.log(`NumberOfRvaAndSizes: ${numberOfRvaAndSizes}`);

// --- Sections ---
const secOff = optOff + sizeOfOptional;
const sections = [];
console.log('\nSections:');
for (let i = 0; i < numSections; i++) {
  const s = secOff + i * 40;
  const name = buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, '');
  const vsize = buf.readUInt32LE(s + 8);
  const vaddr = buf.readUInt32LE(s + 12);
  const rawsize = buf.readUInt32LE(s + 16);
  const rawptr = buf.readUInt32LE(s + 20);
  const chars = buf.readUInt32LE(s + 36);
  sections.push({ name, vsize, vaddr, rawsize, rawptr, chars });
  console.log(`  ${name.padEnd(10)} VA=0x${vaddr.toString(16).padStart(8, '0')} VS=0x${vsize.toString(16).padStart(8, '0')} RAW=0x${rawptr.toString(16).padStart(8, '0')} RS=0x${rawsize.toString(16).padStart(8, '0')} CH=0x${chars.toString(16)}`);
}

// RVA -> file offset
function rvaToOff(rva) {
  for (const s of sections) {
    if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawsize)) {
      let off = s.rawptr + (rva - s.vaddr);
      if (rva - s.vaddr < s.rawsize) return off;
      return -1; // virtual only (bss)
    }
  }
  return -1;
}

// --- Data directories of interest (exports, imports) ---
const ddOff = optOff + 112;
const ddNames = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Relocation', 'Debug', 'Arch', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT', 'DelayImport', 'CLR', 'Reserved'];
console.log('\nData directories:');
for (let i = 0; i < numberOfRvaAndSizes; i++) {
  const rva = buf.readUInt32LE(ddOff + i * 8);
  const size = buf.readUInt32LE(ddOff + i * 8 + 4);
  if (rva) console.log(`  ${ddNames[i]}: RVA=0x${rva.toString(16)} size=0x${size.toString(16)}`);
}

// --- Exports ---
const expRva = buf.readUInt32LE(ddOff + 0);
if (expRva) {
  const eo = rvaToOff(expRva);
  const ordinalBase = buf.readUInt32LE(eo + 16);
  const nFuncs = buf.readUInt32LE(eo + 20);
  const nNames = buf.readUInt32LE(eo + 24);
  const addrFuncsRva = buf.readUInt32LE(eo + 28);
  const addrNamesRva = buf.readUInt32LE(eo + 32);
  console.log(`\nExports: ordinalBase=${ordinalBase} nFuncs=${nFuncs} nNames=${nNames}`);
  for (let i = 0; i < nNames; i++) {
    const nameRva = buf.readUInt32LE(rvaToOff(addrNamesRva) + i * 4);
    const funcRva = buf.readUInt32LE(rvaToOff(addrFuncsRva) + i * 4);
    const name = buf.slice(rvaToOff(nameRva), rvaToOff(nameRva) + 128).toString('ascii').replace(/\0.*$/, '');
    console.log(`  ${name} (rva 0x${funcRva.toString(16)})`);
  }
}

// --- ASCII strings extraction ---
// min length 4; record VA and file offset
const minLen = 4;
const strings = [];
let cur = [];
let start = -1;
for (let i = 0; i < buf.length; i++) {
  const c = buf[i];
  const printable = (c >= 0x20 && c <= 0x7e);
  if (printable) {
    if (cur.length === 0) start = i;
    cur.push(c);
  } else {
    if (cur.length >= minLen) {
      // compute VA: find section containing this file offset
      let va = null;
      for (const s of sections) {
        if (i - 1 >= s.rawptr && i - 1 < s.rawptr + s.rawsize) {
          va = BigInt(imageBase) + BigInt(s.vaddr + (i - 1 - s.rawptr));
          break;
        }
      }
      if (va !== null) {
        strings.push({ off: start, va, len: cur.length, text: Buffer.from(cur).toString('ascii') });
      }
    }
    cur = [];
  }
}
console.log(`\nTotal ASCII strings (>=${minLen} chars, mapped to VA): ${strings.length}`);

// Save all strings
const allLines = strings.map(s => `0x${s.va.toString(16).padStart(12, '0')}\t${s.len}\t${s.text.replace(/\t/g, ' ')}`);
fs.writeFileSync(path.join(outDir, 'strings_all.txt'), allLines.join('\n'), 'utf8');
console.log(`Wrote ${path.join(outDir, 'strings_all.txt')}`);

// also save a machine-readable json
fs.writeFileSync(path.join(outDir, 'strings_all.json'), JSON.stringify(strings.map(s => ({ off: s.off, va: '0x' + s.va.toString(16), len: s.len, text: s.text }))), 'utf8');
