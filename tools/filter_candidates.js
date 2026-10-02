// Extract "display-like" strings from the unpacked DLL for localization review.
// Excludes snake_case ids, RTTI, paths, library noise.
'use strict';
const fs = require('fs');
const path = require('path');
const dir = process.argv[2] || path.join(__dirname, '..', 'out2');
const strings = JSON.parse(fs.readFileSync(path.join(dir, 'strings_all.json'), 'utf8'));

function isDisplayLike(s) {
  const t = s.text;
  if (t.length < 4 || t.length > 300) return false;
  // all chars must be printable ascii
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  // exclude snake_case / ids / paths / filenames / extensions
  if (/^[a-z0-9_\-./\\:<>+~]+$/.test(t)) return false;
  // exclude RTTI and mangled names
  if (t.startsWith('.?A') || t.startsWith('??_')) return false;
  // require human traits: a space, or an uppercase letter, or a digit with letters
  const hasLower = /[a-z]/.test(t);
  const hasUpper = /[A-Z]/.test(t);
  const hasSpace = t.includes(' ');
  if (!hasLower) return false;
  if (!hasUpper && !hasSpace) return false;
  // letters should dominate
  const letters = (t.match(/[A-Za-z]/g) || []).length;
  if (letters / t.length < 0.55) return false;
  // exclude common library markers
  if (/^(imgui|ImGui|dx|d3d|D3D|Direct|stb_|nlohmann|json|fmt |sol::|lua_|glm|ktx|vk|Vk|Vk|opengl|OpenGL|dinput|xinput|XInput|Win32|Windows|shader|Shader|hlsl|HLSL)/.test(t)) return false;
  if (/(exception|error|failed|invalid|warning|assert|debug|registry|\.dll|\.exe|\.pdb|\.txt|\.json|\.log|HRESULT|0x[0-9a-fA-F]{4,})/.test(t) && !/ /.test(t)) return false;
  return true;
}

const cands = strings.filter(isDisplayLike);
console.log('candidates:', cands.length);
// cluster by address region to see where trainer strings live
const buckets = {};
for (const c of cands) {
  const hi = (BigInt(c.va) >> 20n).toString(16); // 1MB buckets
  (buckets[hi] ||= []).push(c);
}
const keys = Object.keys(buckets).sort();
for (const k of keys) {
  console.log(`  0x${(BigInt(k) << 20n).toString(16)} : ${buckets[k].length}`);
}
fs.writeFileSync(path.join(dir, 'candidates.txt'), cands.map(c => `0x${BigInt(c.va).toString(16).padStart(12, '0')}\t${c.len}\t${c.text}`).join('\n'), 'utf8');
