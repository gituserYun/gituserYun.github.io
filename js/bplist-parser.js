/*!
 * bplist-parser.js
 * -----------------------------------------------------------------------
 * 브라우저용 최소 구현 Property List 파서 (XML plist + 바이너리 bplist00).
 * Python plistlib.load()의 대체 역할 - iOS Info.plist / *.entitlements 는
 * XML 또는 바이너리(bplist00) 두 형식 모두로 존재할 수 있어서 둘 다 지원한다.
 *
 * 지원 타입: null, bool, int, real, date(ISO 문자열로 변환), data(Uint8Array),
 *           ascii/utf16 string, array, set, dict, uid({UID:n})
 * 지원하지 않는 것: NSKeyedArchiver의 UID 참조를 실제 객체로 역참조하는 것
 *                  (필요한 스캔 목적상 문자열/딕셔너리 구조만 있으면 충분함)
 */

function isBinaryPlist(buffer) {
  const bytes = new Uint8Array(buffer, 0, Math.min(8, buffer.byteLength));
  let magic = '';
  for (let i = 0; i < bytes.length; i++) magic += String.fromCharCode(bytes[i]);
  return magic.startsWith('bplist');
}

function parseBinaryPlist(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  const len = buffer.byteLength;
  if (len < 32) throw new Error('bplist too small');

  function readUInt(offset, size) {
    let result = 0;
    for (let i = 0; i < size; i++) {
      result = result * 256 + view.getUint8(offset + i);
    }
    return result;
  }

  // 트레일러 (파일 마지막 32바이트)
  const trailerOffset = len - 32;
  const offsetSize = view.getUint8(trailerOffset + 6);
  const objectRefSize = view.getUint8(trailerOffset + 7);
  const numObjects = readUInt(trailerOffset + 8, 8);
  const topObject = readUInt(trailerOffset + 16, 8);
  const offsetTableOffset = readUInt(trailerOffset + 24, 8);

  const offsetTable = [];
  for (let i = 0; i < numObjects; i++) {
    offsetTable.push(readUInt(offsetTableOffset + i * offsetSize, offsetSize));
  }

  const cache = new Array(numObjects);

  function readLength(offset, objInfo) {
    if (objInfo !== 0x0f) return { count: objInfo, headerLen: 1 };
    const intMarker = bytes[offset + 1];
    const intByteCount = 1 << (intMarker & 0x0f);
    const count = readUInt(offset + 2, intByteCount);
    return { count, headerLen: 2 + intByteCount };
  }

  function asciiToString(start, count) {
    let s = '';
    for (let i = 0; i < count; i++) s += String.fromCharCode(bytes[start + i]);
    return s;
  }

  function utf16beToString(start, count) {
    let s = '';
    for (let i = 0; i < count; i++) s += String.fromCharCode(view.getUint16(start + i * 2, false));
    return s;
  }

  function readSignedInt(offset, byteCount) {
    if (byteCount === 8) {
      const big = view.getBigUint64(offset, false);
      return Number(BigInt.asIntN(64, big));
    }
    return readUInt(offset, byteCount);
  }

  function readObjectAt(index) {
    if (cache[index] !== undefined) return cache[index];
    const offset = offsetTable[index];
    const marker = bytes[offset];
    const objType = (marker & 0xf0) >> 4;
    const objInfo = marker & 0x0f;
    let result;

    switch (objType) {
      case 0x0:
        if (objInfo === 0x8) result = false;
        else if (objInfo === 0x9) result = true;
        else result = null;
        break;
      case 0x1: {
        const byteCount = 1 << objInfo;
        result = readSignedInt(offset + 1, byteCount);
        break;
      }
      case 0x2: {
        const byteCount = 1 << objInfo;
        result = byteCount === 4 ? view.getFloat32(offset + 1, false) : view.getFloat64(offset + 1, false);
        break;
      }
      case 0x3: {
        const seconds = view.getFloat64(offset + 1, false);
        result = new Date((seconds + 978307200) * 1000).toISOString();
        break;
      }
      case 0x4: {
        const { count, headerLen } = readLength(offset, objInfo);
        result = bytes.slice(offset + headerLen, offset + headerLen + count);
        break;
      }
      case 0x5: {
        const { count, headerLen } = readLength(offset, objInfo);
        result = asciiToString(offset + headerLen, count);
        break;
      }
      case 0x6: {
        const { count, headerLen } = readLength(offset, objInfo);
        result = utf16beToString(offset + headerLen, count);
        break;
      }
      case 0x8: {
        const byteCount = objInfo + 1;
        result = { UID: readUInt(offset + 1, byteCount) };
        break;
      }
      case 0xa:
      case 0xc: {
        const { count, headerLen } = readLength(offset, objInfo);
        const refs = [];
        for (let i = 0; i < count; i++) {
          refs.push(readUInt(offset + headerLen + i * objectRefSize, objectRefSize));
        }
        cache[index] = [];
        result = refs.map(readObjectAt);
        break;
      }
      case 0xd: {
        const { count, headerLen } = readLength(offset, objInfo);
        const keyRefs = [];
        const valRefs = [];
        for (let i = 0; i < count; i++) {
          keyRefs.push(readUInt(offset + headerLen + i * objectRefSize, objectRefSize));
        }
        for (let i = 0; i < count; i++) {
          valRefs.push(readUInt(offset + headerLen + (count + i) * objectRefSize, objectRefSize));
        }
        result = {};
        cache[index] = result;
        for (let i = 0; i < count; i++) {
          const key = readObjectAt(keyRefs[i]);
          result[String(key)] = readObjectAt(valRefs[i]);
        }
        break;
      }
      default:
        result = null;
    }

    cache[index] = result;
    return result;
  }

  return readObjectAt(topObject);
}

function parseXmlPlist(xmlText) {
  const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  if (doc.querySelector('parsererror')) throw new Error('XML plist parse error');
  const plistEl = doc.documentElement;
  const root = plistEl.querySelector(':scope > *');
  return parseXmlNode(root);
}

function parseXmlNode(node) {
  if (!node) return null;
  switch (node.tagName) {
    case 'dict': {
      const result = {};
      const children = Array.from(node.children);
      for (let i = 0; i < children.length; i += 2) {
        const keyEl = children[i];
        const valEl = children[i + 1];
        if (!keyEl || keyEl.tagName !== 'key') continue;
        result[keyEl.textContent] = parseXmlNode(valEl);
      }
      return result;
    }
    case 'array':
      return Array.from(node.children).map(parseXmlNode);
    case 'string':
      return node.textContent;
    case 'integer':
      return parseInt(node.textContent, 10);
    case 'real':
      return parseFloat(node.textContent);
    case 'true':
      return true;
    case 'false':
      return false;
    case 'date':
      return node.textContent;
    case 'data':
      return node.textContent;
    default:
      return null;
  }
}

// buffer: ArrayBuffer
function parsePlist(buffer) {
  if (isBinaryPlist(buffer)) {
    return parseBinaryPlist(buffer);
  }
  const text = new TextDecoder('utf-8').decode(buffer);
  return parseXmlPlist(text);
}

window.PlistParser = { parsePlist, isBinaryPlist, parseBinaryPlist, parseXmlPlist };
