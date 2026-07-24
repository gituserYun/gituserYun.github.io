/*!
 * ipa_all_scanner.js
 * -----------------------------------------------------------------------
 * ipa_api_key_scanner.py / ipa_url_scanner.py / ipa_scheme_scanner.py
 * 3개 파이썬 스크립트의 탐지 로직을 브라우저(JS)로 이식한 버전.
 * .ipa 파일을 서버 업로드 없이 클라이언트에서 JSZip으로 직접 파싱하고,
 * URL / API-KEY / Scheme 3가지 스캔을 동시에 수행해 SheetJS로 3-sheet
 * 엑셀 파일을 생성, File System Access API로 로컬 폴더에 저장한다.
 */

// ──────────────────────────────────────────────
// 공통 상수
// ──────────────────────────────────────────────
const SCAN_ROOT_FOLDER_NAME = 'gituseryun_scan';
const DEFAULT_MAX_BINARY_MB = 300;

const SKIP_DIR_NAMES = new Set(['CVS', '.git', '__MACOSX']);

const TEXT_TARGET_EXTENSIONS = new Set([
  '.xml', '.json', '.properties', '.gradle', '.java',
  '.kt', '.smali', '.txt', '.yaml', '.yml', '.cfg', '.ini',
  '.html', '.js',
  '.m', '.mm', '.swift', '.h', '.strings',
  '.pch', '.storyboard', '.xib',
]);

const MACHO_MAGIC_HEX = new Set(['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca']);

// ──────────────────────────────────────────────
// API-KEY 탐지 패턴 (ipa_api_key_scanner.py PATTERNS 이식)
// ──────────────────────────────────────────────
const API_KEY_PATTERNS = [
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'Google OAuth Client ID', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/ },
  { name: 'Firebase App ID', regex: /1:[0-9]+:(android|ios):[0-9a-f]{20,}/ },
  { name: 'Firebase Storage Bucket', regex: /[a-z0-9\-]+\.firebasestorage\.app/ },
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Access Key', regex: /aws.{0,20}secret.{0,20}["']([0-9a-zA-Z/+]{40})["']/i },
  { name: 'Kakao App Key', regex: /kakao[_\-]?(app|native|rest)?[_\-]?key["\s=>:]+["']?([0-9a-f]{32})["']?/i },
  { name: 'Branch.io Key', regex: /key_(live|test)_[0-9A-Za-z]{32,}/ },
  { name: 'Sendbird App/Agent ID', regex: /[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/ },
  { name: 'Facebook App ID', regex: /facebook[_\-]?app[_\-]?id["\s=>:]+["']?([0-9]{10,20})["']?/i },
  { name: 'Facebook Client Token', regex: /(FacebookClientToken|fb[_\-]?client[_\-]?token)["\s=>:]+["']?([0-9a-f]{32})["']?/i },
  { name: 'LINE Channel ID', regex: /line[_\-]?channel[_\-]?id["\s=>:]+["']?([0-9]{8,12})["']?/i },
  { name: 'T-map API Key', regex: /l7xx[0-9a-f]{32}/ },
  { name: 'Zendesk Account Key', regex: /zendesk[_\-]?(prod[_\-]?)?account[_\-]?key["\s=>:]+["']?([A-Za-z0-9]{32,})["']?/i },
  { name: 'Zendesk OAuth Credential', regex: /zendesk[_\-]?(prod[_\-]?)?oauth[_\-]?credential["\s=>:]+["']?([A-Za-z0-9]{32,})["']?/i },
  { name: 'Zendesk App ID', regex: /zendesk[_\-]?(prod[_\-]?)?app[_\-]?id["\s=>:]+["']?([0-9a-f]{40,})["']?/i },
  { name: 'Mixpanel Token', regex: /mixpanel[_\-]?token["\s=>:]+["']?([0-9a-f]{32})["']?/i },
  { name: 'Amplitude API Key', regex: /amplitude[_\-]?(api)?[_\-]?key["\s=>:]+["']?([0-9a-f]{32})["']?/i },
  { name: 'APNs / Push Key Reference', regex: /(apns|push)[_\-]?(auth)?[_\-]?key["\s=>:]+["']?([A-Za-z0-9\-_]{10,})["']?/i },
  { name: 'Adjust App Token', regex: /adjust[_\-]?(app)?[_\-]?token["\s=>:]+["']?([0-9a-z]{12})["']?/i },
  { name: 'Stripe Key', regex: /(?:sk|pk)_(live|test)_[0-9A-Za-z]{24,}/ },
  { name: 'Generic API Key', regex: /(api[_\-]?key|apikey)\s*[=:>"\s]+\s*["']?([A-Za-z0-9\-_]{20,})["']?/i },
  { name: 'Generic Secret Key', regex: /(secret[_\-]?key|client[_\-]?secret)\s*[=:>"\s]+\s*["']?([A-Za-z0-9\-_]{20,})["']?/i },
  { name: 'Generic Token', regex: /(access[_\-]?token|auth[_\-]?token)\s*[=:>"\s]+\s*["']?([A-Za-z0-9\-_.]{20,})["']?/i },
  { name: 'Hardcoded Password', regex: /(password|passwd|pwd)\s*[=:>"\s]+\s*["']([^"']{6,})["']/i },
  { name: 'Private Key Header', regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/ },
];

const PLIST_SUSPICIOUS_KEY_HINTS = [
  'apikey', 'api_key', 'secret', 'token', 'password', 'passwd',
  'clientid', 'client_id', 'clientsecret', 'client_secret',
  'accesskey', 'access_key', 'appkey', 'app_key',
];

const API_IGNORE_VALUES = [
  'YOUR_API_KEY', 'API_KEY_HERE', 'INSERT_API_KEY',
  'your_key_here', 'example', 'placeholder',
];

// ──────────────────────────────────────────────
// URL 탐지 패턴 (ipa_url_scanner.py URL_PATTERNS 이식)
// ──────────────────────────────────────────────
const URL_PATTERNS = [
  { name: 'HTTP/HTTPS URL', regex: /https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]{10,}/g },
  { name: 'IP-based URL', regex: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?[/A-Za-z0-9\-._~:?#[\]@!$&'()*+,;=%]*/g },
  { name: 'Localhost URL', regex: /https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?[/A-Za-z0-9\-._~:?#[\]@!$&'()*+,;=%]*/g },
  { name: 'WebSocket URL', regex: /wss?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]{6,}/g },
  { name: 'Deep Link / Custom Scheme', regex: /(?<![a-zA-Z])[a-z][a-z0-9+\-.]{2,}:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]{4,}/g },
  { name: 'Hardcoded Domain String', regex: /["']([a-zA-Z0-9\-]+\.(?:co\.kr|com|net|io|ai|app|dev|internal|local|kr)(?:\/[^\s"']*)?)["']/g },
  { name: 'API Endpoint Path', regex: /["'](?:\/api\/v?\d*|\/v\d+|\/rest|\/graphql|\/gql)[/A-Za-z0-9\-._{}]*["']/g },
];

const PLIST_URL_KEY_HINTS = [
  'url', 'baseurl', 'endpoint', 'host', 'domain', 'server',
  'apihost', 'apiurl', 'webview', 'link',
];

const ATS_EXCEPTION_KEY_HINTS = ['nsexceptiondomains', 'nsallowsarbitraryloads'];

const URL_IGNORE_VALUES = [
  'example.com', 'schemas.android.com', 'xmlpull.org',
  'www.w3.org', 'schema.org', 'localhost:8080',
  'your-domain', 'your_domain', 'placeholder',
  '127.0.0.1:8080', '0.0.0.0',
  'apple.com/DTDs', 'apple.com/xml', 'developer.apple.com',
];

const HIGH_INTEREST_KEYWORDS = [
  'api', 'auth', 'login', 'token', 'secret', 'admin',
  'internal', 'dev', 'staging', 'prod', 'payment', 'pay',
  'user', 'account', 'private', 'secure', 'upload', 'download',
];

// ──────────────────────────────────────────────
// Scheme(딥링크) 탐지 패턴 (ipa_scheme_scanner.py 이식)
// ──────────────────────────────────────────────
const SCHEME_URI_REGEX = /(?<![a-zA-Z0-9+\-.])([a-zA-Z][a-zA-Z0-9+\-.]{1,30}):\/\/([A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]{1,400})/g;

const COMMON_NOISE_SCHEMES = new Set([
  'http', 'https', 'ws', 'wss', 'ftp', 'ftps', 'file', 'data',
  'javascript', 'about', 'chrome', 'res', 'blob', 'content',
  'android-app', 'market', 'geo', 'sms', 'callto',
  'xmlns', 'xml', 'urn', 'schemas-microsoft-com',
]);

// ──────────────────────────────────────────────
// 공통 유틸
// ──────────────────────────────────────────────
function getExtension(path) {
  const base = path.split('/').pop();
  const dotIdx = base.lastIndexOf('.');
  return dotIdx === -1 ? '' : base.slice(dotIdx).toLowerCase();
}

function includesAny(haystackLower, needles) {
  return needles.some((n) => haystackLower.includes(n));
}

function shouldSkipApiValue(value) {
  const v = value.toLowerCase();
  return API_IGNORE_VALUES.some((ig) => v.includes(ig.toLowerCase()));
}

function shouldSkipUrlValue(value) {
  const v = value.toLowerCase();
  return URL_IGNORE_VALUES.some((ig) => v.includes(ig.toLowerCase()));
}

function isHighInterestUrl(value) {
  const v = value.toLowerCase();
  return includesAny(v, HIGH_INTEREST_KEYWORDS);
}

function extractHostPath(urlStr) {
  try {
    const u = new URL(urlStr);
    return { host: u.host || null, path: u.pathname || null };
  } catch (e) {
    return { host: null, path: null };
  }
}

function safeDecodeText(buf) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(buf);
  } catch (e) {
    return '';
  }
}

function isMachOBinary(bytes4) {
  if (!bytes4 || bytes4.length < 4) return false;
  let hex = '';
  for (let i = 0; i < 4; i++) hex += bytes4[i].toString(16).padStart(2, '0');
  return MACHO_MAGIC_HEX.has(hex);
}

function todayDateString() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function sanitizeFilenamePart(name) {
  return name.replace(/[\\/:*?"<>|]/g, '_');
}

// ──────────────────────────────────────────────
// plist 재귀 순회 (원본 3개 스크립트의 세 가지 다른 순회 방식을 그대로 이식)
// ──────────────────────────────────────────────
// api-key / url 스캐너용: dict의 "값이 string인 경우"만 검사 (배열의 순수 문자열 항목은 검사 안 함 - 원본 동일)
function walkPlistDictStrings(obj, keyPath, visit) {
  if (obj instanceof Uint8Array) return;
  if (Array.isArray(obj)) {
    obj.forEach((item, i) => walkPlistDictStrings(item, `${keyPath}[${i}]`, visit));
    return;
  }
  if (obj !== null && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const newPath = keyPath ? `${keyPath}.${k}` : String(k);
      if (typeof v === 'string') {
        visit(k, newPath, v);
      } else {
        walkPlistDictStrings(v, newPath, visit);
      }
    }
  }
}

// scheme 스캐너용: dict/array 안의 모든 string 리프를 검사 (원본 scan_plist_file_for_schemes와 동일)
function walkPlistAllStrings(obj, keyPath, visit) {
  if (obj instanceof Uint8Array) return;
  if (Array.isArray(obj)) {
    obj.forEach((item, i) => walkPlistAllStrings(item, `${keyPath}[${i}]`, visit));
  } else if (obj !== null && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      walkPlistAllStrings(v, keyPath ? `${keyPath}.${k}` : String(k), visit);
    }
  } else if (typeof obj === 'string') {
    visit(keyPath, obj);
  }
}

// ──────────────────────────────────────────────
// 텍스트 파일 스캐너
// ──────────────────────────────────────────────
function scanTextForApiKeys(filePath, content, findings) {
  const lines = content.split(/\r\n|\r|\n/);
  lines.forEach((line, idx) => {
    for (const pat of API_KEY_PATTERNS) {
      const m = line.match(pat.regex);
      if (m) {
        const matchedValue = m[0];
        if (shouldSkipApiValue(matchedValue)) continue;
        findings.push({
          filePath, lineNumber: idx + 1, credentialType: pat.name,
          matchedLine: line.trim().slice(0, 200), matchedValue,
        });
      }
    }
  });
}

function scanTextForUrls(filePath, content, findings) {
  const lines = content.split(/\r\n|\r|\n/);
  lines.forEach((line, idx) => {
    const seen = new Set();
    for (const pat of URL_PATTERNS) {
      for (const m of line.matchAll(pat.regex)) {
        const matchedValue = m[0].replace(/^["']+|["']+$/g, '');
        if (seen.has(matchedValue) || shouldSkipUrlValue(matchedValue)) continue;
        seen.add(matchedValue);
        const { host, path } = extractHostPath(matchedValue);
        findings.push({
          filePath, lineNumber: idx + 1, urlType: pat.name,
          matchedLine: line.trim().slice(0, 200), matchedValue,
          host, path, isHighInterest: isHighInterestUrl(matchedValue),
        });
      }
    }
  });
}

function scanTextForSchemes(filePath, content, usages) {
  const lines = content.split(/\r\n|\r|\n/);
  lines.forEach((line, idx) => {
    for (const m of line.matchAll(SCHEME_URI_REGEX)) {
      usages.push({
        scheme: m[1], fullUri: m[0], rest: m[2],
        filePath, lineNumber: idx + 1, sourceKind: 'source',
      });
    }
  });
}

// ──────────────────────────────────────────────
// plist 전용 스캐너
// ──────────────────────────────────────────────
function scanPlistForApiKeys(filePath, plistObj, findings) {
  walkPlistDictStrings(plistObj, '', (key, keyPath, value) => {
    const keyLower = String(key).toLowerCase().replace(/_/g, '').replace(/-/g, '');
    if (PLIST_SUSPICIOUS_KEY_HINTS.some((h) => keyLower.includes(h.replace(/_/g, '')))) {
      if (value && !shouldSkipApiValue(value) && value.length >= 6) {
        findings.push({
          filePath, lineNumber: -1, credentialType: `Plist Suspicious Key (${key})`,
          matchedLine: `${keyPath} = ${value}`.slice(0, 200), matchedValue: value,
        });
      }
    }
    for (const pat of API_KEY_PATTERNS) {
      const m = value.match(pat.regex);
      if (m && !shouldSkipApiValue(m[0])) {
        findings.push({
          filePath, lineNumber: -1, credentialType: pat.name,
          matchedLine: `${keyPath} = ${value}`.slice(0, 200), matchedValue: m[0],
        });
      }
    }
  });
}

function scanPlistForUrls(filePath, plistObj, findings) {
  const seen = new Set();
  walkPlistDictStrings(plistObj, '', (key, keyPath, value) => {
    for (const pat of URL_PATTERNS) {
      for (const m of value.matchAll(pat.regex)) {
        const matchedValue = m[0].replace(/^["']+|["']+$/g, '');
        if (seen.has(matchedValue) || shouldSkipUrlValue(matchedValue)) continue;
        seen.add(matchedValue);
        const { host, path } = extractHostPath(matchedValue);
        findings.push({
          filePath, lineNumber: -1, urlType: pat.name,
          matchedLine: `${keyPath} = ${value}`.slice(0, 200), matchedValue,
          host, path, isHighInterest: isHighInterestUrl(matchedValue),
        });
      }
    }

    const keyLower = String(key).toLowerCase().replace(/_/g, '').replace(/-/g, '');
    if (includesAny(keyLower, PLIST_URL_KEY_HINTS)) {
      if (value && !seen.has(value) && !shouldSkipUrlValue(value)) {
        seen.add(value);
        findings.push({
          filePath, lineNumber: -1, urlType: 'Plist URL-like Key',
          matchedLine: `${keyPath} = ${value}`.slice(0, 200), matchedValue: value,
          host: null, path: null, isHighInterest: true,
        });
      }
    }
    if (includesAny(keyLower, ATS_EXCEPTION_KEY_HINTS)) {
      const dedupKey = `ATS:${keyPath}`;
      if (!seen.has(dedupKey)) {
        seen.add(dedupKey);
        findings.push({
          filePath, lineNumber: -1, urlType: 'ATS Exception (평문 HTTP 허용 가능성)',
          matchedLine: `${keyPath} = ${value}`.slice(0, 200), matchedValue: String(value),
          host: null, path: null, isHighInterest: true,
        });
      }
    }
  });
}

function scanPlistForSchemes(filePath, plistObj, usages) {
  walkPlistAllStrings(plistObj, '', (keyPath, value) => {
    for (const m of value.matchAll(SCHEME_URI_REGEX)) {
      usages.push({
        scheme: m[1], fullUri: m[0], rest: m[2],
        filePath, lineNumber: -1, sourceKind: 'plist',
      });
    }
  });
}

function extractSchemeDefinitionsFromInfoPlist(filePath, plistObj) {
  const defs = [];
  const urlTypes = plistObj && plistObj.CFBundleURLTypes;
  if (Array.isArray(urlTypes)) {
    for (const entry of urlTypes) {
      if (!entry || typeof entry !== 'object') continue;
      const schemes = entry.CFBundleURLSchemes || [];
      const urlName = entry.CFBundleURLName || '';
      const role = entry.CFBundleTypeRole || '';
      for (const scheme of schemes) {
        if (typeof scheme === 'string' && scheme) {
          const detail = `CFBundleURLName=${urlName}` + (role ? `, Role=${role}` : '');
          defs.push({ scheme, kind: 'CFBundleURLTypes', detail, filePath });
        }
      }
    }
  }
  const querySchemes = plistObj && plistObj.LSApplicationQueriesSchemes;
  if (Array.isArray(querySchemes)) {
    for (const scheme of querySchemes) {
      if (typeof scheme === 'string' && scheme) {
        defs.push({ scheme, kind: 'LSApplicationQueriesSchemes', detail: 'canOpenURL 등으로 연동 가능한 외부 스킴', filePath });
      }
    }
  }
  return defs;
}

function extractAssociatedDomains(filePath, plistObj) {
  const domains = plistObj && plistObj['com.apple.developer.associated-domains'];
  if (!Array.isArray(domains)) return [];
  const defs = [];
  for (const d of domains) {
    if (typeof d === 'string' && d) {
      defs.push({ scheme: 'https', kind: 'AssociatedDomains', detail: d, filePath });
    }
  }
  return defs;
}

// ──────────────────────────────────────────────
// Mach-O 바이너리 strings 스캔 (scheme 전용, 원본과 동일 범위)
// ──────────────────────────────────────────────
function scanBinaryForSchemes(filePath, arrayBuffer, usages, maxBytes, log) {
  if (arrayBuffer.byteLength > maxBytes) {
    log(`  [!] 건너뜀 (크기 초과 ${(arrayBuffer.byteLength / 1024 / 1024).toFixed(1)}MB): ${filePath}`);
    return;
  }
  const bytes = new Uint8Array(arrayBuffer);
  let text = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    text += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  const stringRunRegex = /[\x20-\x7e]{4,}/g;
  for (const run of text.matchAll(stringRunRegex)) {
    for (const m of run[0].matchAll(SCHEME_URI_REGEX)) {
      usages.push({
        scheme: m[1], fullUri: m[0], rest: m[2],
        filePath, lineNumber: -1, sourceKind: 'binary',
      });
    }
  }
}

// ──────────────────────────────────────────────
// 분류 / 중복 제거 (ipa_scheme_scanner.py classify_usages / dedup_usages 이식)
// ──────────────────────────────────────────────
function classifyUsages(usages, definitions) {
  const registered = new Set(definitions.filter((d) => d.kind === 'CFBundleURLTypes').map((d) => d.scheme.toLowerCase()));
  const queried = new Set(definitions.filter((d) => d.kind === 'LSApplicationQueriesSchemes').map((d) => d.scheme.toLowerCase()));
  const result = [];
  for (const u of usages) {
    const s = u.scheme.toLowerCase();
    if (registered.has(s)) u.classification = 'REGISTERED';
    else if (queried.has(s)) u.classification = 'QUERIED';
    else if (COMMON_NOISE_SCHEMES.has(s)) continue;
    else u.classification = 'UNREGISTERED';
    result.push(u);
  }
  return result;
}

function dedupUsages(usages) {
  const seen = new Set();
  const result = [];
  for (const u of usages) {
    const key = `${u.filePath} ${u.lineNumber} ${u.fullUri}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(u);
  }
  return result;
}

// ──────────────────────────────────────────────
// IPA(zip) 전체 스캔
// ──────────────────────────────────────────────
async function processIpa(ipaFile, options, log, onProgress) {
  log(`[*] IPA 파싱 중: ${ipaFile.name} (${(ipaFile.size / 1024 / 1024).toFixed(1)}MB)`);
  const arrayBuffer = await ipaFile.arrayBuffer();
  const zip = await JSZip.loadAsync(arrayBuffer);

  const entries = [];
  zip.forEach((relPath, zipEntry) => {
    if (zipEntry.dir) return;
    const parts = relPath.split('/');
    if (parts.some((p) => SKIP_DIR_NAMES.has(p))) return;
    entries.push(zipEntry);
  });
  log(`[+] 대상 파일 ${entries.length}개 발견, 스캔 시작...`);

  const apiKeyFindings = [];
  const urlFindings = [];
  const schemeUsages = [];
  const schemeDefinitions = [];

  let done = 0;
  for (const entry of entries) {
    const relPath = entry.name;
    const ext = getExtension(relPath);
    const baseName = relPath.split('/').pop();

    try {
      if (ext === '.plist') {
        const buf = await entry.async('arraybuffer');
        let plistObj = null;
        try {
          plistObj = window.PlistParser.parsePlist(buf);
        } catch (e) {
          const text = safeDecodeText(buf);
          scanTextForApiKeys(relPath, text, apiKeyFindings);
          scanTextForUrls(relPath, text, urlFindings);
          scanTextForSchemes(relPath, text, schemeUsages);
        }
        if (plistObj && typeof plistObj === 'object') {
          scanPlistForApiKeys(relPath, plistObj, apiKeyFindings);
          scanPlistForUrls(relPath, plistObj, urlFindings);
          scanPlistForSchemes(relPath, plistObj, schemeUsages);
          if (baseName === 'Info.plist') {
            schemeDefinitions.push(...extractSchemeDefinitionsFromInfoPlist(relPath, plistObj));
          }
        }
      } else if (ext === '.entitlements') {
        const buf = await entry.async('arraybuffer');
        const text = safeDecodeText(buf);
        scanTextForApiKeys(relPath, text, apiKeyFindings);
        scanTextForUrls(relPath, text, urlFindings);
        scanTextForSchemes(relPath, text, schemeUsages);
        try {
          const plistObj = window.PlistParser.parsePlist(buf);
          schemeDefinitions.push(...extractAssociatedDomains(relPath, plistObj));
        } catch (e) {
          // entitlements가 plist 형식이 아니면 무시 (텍스트 스캔은 이미 수행됨)
        }
      } else if (TEXT_TARGET_EXTENSIONS.has(ext)) {
        const text = await entry.async('string');
        scanTextForApiKeys(relPath, text, apiKeyFindings);
        scanTextForUrls(relPath, text, urlFindings);
        scanTextForSchemes(relPath, text, schemeUsages);
      } else if (!options.skipBinary && (ext === '.dylib' || ext === '.so' || ext === '')) {
        const buf = await entry.async('arraybuffer');
        const head = new Uint8Array(buf.slice(0, 4));
        if (ext === '.dylib' || ext === '.so' || isMachOBinary(head)) {
          scanBinaryForSchemes(relPath, buf, schemeUsages, options.maxBinaryBytes, log);
        }
      }
    } catch (e) {
      log(`  [!] 스캔 실패: ${relPath} (${e.message})`);
    }

    done += 1;
    if (done % 25 === 0 || done === entries.length) {
      onProgress(done, entries.length);
    }
  }

  const dedupedSchemeUsages = dedupUsages(schemeUsages);
  const classifiedSchemeUsages = classifyUsages(dedupedSchemeUsages, schemeDefinitions);

  log(`[+] 스캔 완료: URL ${urlFindings.length}건 / API-KEY ${apiKeyFindings.length}건 / Scheme ${classifiedSchemeUsages.length}건`);

  return {
    apiKeyFindings,
    urlFindings,
    schemeDefinitions,
    schemeUsages: classifiedSchemeUsages,
  };
}

// ──────────────────────────────────────────────
// 엑셀(3-sheet) 생성
// ──────────────────────────────────────────────
function autosizeColumns(sheet, rows) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  sheet['!cols'] = headers.map((h) => {
    let maxLen = h.length;
    for (const row of rows) {
      const v = row[h];
      if (v != null) maxLen = Math.max(maxLen, String(v).length);
    }
    return { wch: Math.min(Math.max(maxLen + 2, 10), 80) };
  });
}

function buildWorkbook(result) {
  const wb = XLSX.utils.book_new();

  const urlRows = result.urlFindings.map((f) => ({
    '유형': f.urlType,
    '파일': f.filePath,
    '라인': f.lineNumber === -1 ? '' : f.lineNumber,
    'URL': f.matchedValue,
    'Host': f.host || '',
    'Path': f.path || '',
    '고관심도': f.isHighInterest ? 'Y' : '',
    '원문': f.matchedLine,
  }));
  const urlSheet = XLSX.utils.json_to_sheet(urlRows);
  autosizeColumns(urlSheet, urlRows);
  XLSX.utils.book_append_sheet(wb, urlSheet, 'URL');

  const apiRows = result.apiKeyFindings.map((f) => ({
    '유형': f.credentialType,
    '파일': f.filePath,
    '라인': f.lineNumber === -1 ? '' : f.lineNumber,
    '매칭값': f.matchedValue,
    '매칭라인': f.matchedLine,
  }));
  const apiSheet = XLSX.utils.json_to_sheet(apiRows);
  autosizeColumns(apiSheet, apiRows);
  XLSX.utils.book_append_sheet(wb, apiSheet, 'API-KEY');

  const defRows = result.schemeDefinitions.map((d) => ({
    '분류': `${d.kind}(등록정보)`,
    'Scheme': d.scheme,
    '경로/상세': d.detail,
    '출처유형': 'plist',
    '파일': d.filePath,
    '라인': '',
  }));
  const usageRows = result.schemeUsages.map((u) => ({
    '분류': u.classification,
    'Scheme': u.scheme,
    '경로/상세': u.rest,
    '출처유형': u.sourceKind,
    '파일': u.filePath,
    '라인': u.lineNumber === -1 ? '' : u.lineNumber,
  }));
  const schemeRows = [...defRows, ...usageRows];
  const schemeSheet = XLSX.utils.json_to_sheet(schemeRows);
  autosizeColumns(schemeSheet, schemeRows);
  XLSX.utils.book_append_sheet(wb, schemeSheet, 'Scheme');

  return wb;
}

// ──────────────────────────────────────────────
// File System Access API - C:\gituseryun_scan 폴더 연결/자동생성 + 저장
// ──────────────────────────────────────────────
const HANDLE_DB_NAME = 'ipa-scanner-fs';
const HANDLE_STORE_NAME = 'handles';
const HANDLE_KEY = 'scanRootHandle';

function openHandleDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(HANDLE_DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(HANDLE_STORE_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function saveRootHandle(handle) {
  const db = await openHandleDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(HANDLE_STORE_NAME, 'readwrite');
    tx.objectStore(HANDLE_STORE_NAME).put(handle, HANDLE_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadRootHandle() {
  const db = await openHandleDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(HANDLE_STORE_NAME, 'readonly');
    const req = tx.objectStore(HANDLE_STORE_NAME).get(HANDLE_KEY);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function clearRootHandle() {
  const db = await openHandleDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(HANDLE_STORE_NAME, 'readwrite');
    tx.objectStore(HANDLE_STORE_NAME).delete(HANDLE_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function isFileSystemAccessSupported() {
  return 'showDirectoryPicker' in window;
}

// 사용자가 최초 1회 선택한 루트(권장: C: 드라이브) 아래에
// gituseryun_scan 폴더가 없으면 자동 생성, 있으면 그대로 재사용
async function connectScanFolder() {
  if (!isFileSystemAccessSupported()) {
    throw new Error('이 브라우저는 폴더 자동 저장 기능(File System Access API)을 지원하지 않습니다. Chrome 또는 Edge 최신 버전을 사용해주세요.');
  }

  let rootHandle = await loadRootHandle();
  let needsPicker = true;

  if (rootHandle) {
    try {
      const perm = await rootHandle.queryPermission({ mode: 'readwrite' });
      if (perm === 'granted') {
        needsPicker = false;
      } else if (perm === 'prompt') {
        const req = await rootHandle.requestPermission({ mode: 'readwrite' });
        needsPicker = req !== 'granted';
      }
    } catch (e) {
      needsPicker = true;
    }
  }

  if (needsPicker) {
    rootHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
    await saveRootHandle(rootHandle);
  }

  const scanFolder = await rootHandle.getDirectoryHandle(SCAN_ROOT_FOLDER_NAME, { create: true });
  return { rootHandle, scanFolder };
}

async function saveWorkbook(scanFolder, filename, wb) {
  const arrayBuf = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([arrayBuf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const fileHandle = await scanFolder.getFileHandle(filename, { create: true });
  const writable = await fileHandle.createWritable();
  await writable.write(blob);
  await writable.close();
}

// ──────────────────────────────────────────────
// UI 바인딩
// ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const logEl = document.getElementById('log');
  const connectBtn = document.getElementById('connect-folder-btn');
  const resetBtn = document.getElementById('reset-folder-btn');
  const folderStatusEl = document.getElementById('folder-status');
  const fileInput = document.getElementById('ipa-file-input');
  const fileNameEl = document.getElementById('ipa-file-name');
  const scanBtn = document.getElementById('scan-btn');
  const progressEl = document.getElementById('progress');
  const summaryEl = document.getElementById('summary');

  let scanFolderHandle = null;
  let selectedFile = null;

  function log(msg) {
    const line = document.createElement('div');
    line.textContent = msg;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function updateScanButtonState() {
    scanBtn.disabled = !(scanFolderHandle && selectedFile);
  }

  if (!isFileSystemAccessSupported()) {
    folderStatusEl.textContent = '이 브라우저는 지원되지 않습니다. Chrome 또는 Edge 최신 버전으로 열어주세요.';
    folderStatusEl.classList.add('status-error');
    connectBtn.disabled = true;
  }

  connectBtn.addEventListener('click', async () => {
    try {
      connectBtn.disabled = true;
      folderStatusEl.textContent = '폴더 선택 창을 확인해주세요... (반드시 C: 드라이브를 선택)';
      const { rootHandle, scanFolder } = await connectScanFolder();
      scanFolderHandle = scanFolder;
      folderStatusEl.textContent = `연결됨: "${rootHandle.name}" 안의 ${SCAN_ROOT_FOLDER_NAME} 폴더 (없으면 자동 생성됨)`;
      folderStatusEl.classList.remove('status-error');
      folderStatusEl.classList.add('status-ok');
      resetBtn.style.display = 'inline-block';
      log(`[+] 저장 폴더 연결 완료: ${rootHandle.name}\\${SCAN_ROOT_FOLDER_NAME}`);
    } catch (e) {
      folderStatusEl.textContent = `폴더 연결 실패: ${e.message}`;
      folderStatusEl.classList.add('status-error');
      log(`[!] 폴더 연결 실패: ${e.message}`);
    } finally {
      connectBtn.disabled = false;
      updateScanButtonState();
    }
  });

  resetBtn.addEventListener('click', async () => {
    await clearRootHandle();
    scanFolderHandle = null;
    folderStatusEl.textContent = '폴더 연결이 초기화되었습니다. 다시 연결해주세요.';
    folderStatusEl.classList.remove('status-ok');
    resetBtn.style.display = 'none';
    log('[*] 저장 폴더 연결 초기화됨');
    updateScanButtonState();
  });

  fileInput.addEventListener('change', () => {
    selectedFile = fileInput.files[0] || null;
    fileNameEl.textContent = selectedFile ? selectedFile.name : '선택된 파일 없음';
    updateScanButtonState();
  });

  scanBtn.addEventListener('click', async () => {
    if (!selectedFile || !scanFolderHandle) return;

    scanBtn.disabled = true;
    logEl.innerHTML = '';
    summaryEl.innerHTML = '';
    progressEl.textContent = '';

    try {
      const options = {
        skipBinary: false,
        maxBinaryBytes: DEFAULT_MAX_BINARY_MB * 1024 * 1024,
      };

      const result = await processIpa(selectedFile, options, log, (done, total) => {
        progressEl.textContent = `진행: ${done}/${total} (${((done / total) * 100).toFixed(1)}%)`;
      });

      const ipaBaseName = sanitizeFilenamePart(selectedFile.name.replace(/\.ipa$/i, ''));
      const filename = `${ipaBaseName}-${todayDateString()}.xlsx`;

      log(`[*] 엑셀 생성 중: ${filename}`);
      const wb = buildWorkbook(result);

      log(`[*] 저장 중: ${SCAN_ROOT_FOLDER_NAME}\\${filename}`);
      await saveWorkbook(scanFolderHandle, filename, wb);
      log(`[+] 저장 완료`);

      summaryEl.innerHTML = `
        <p><strong>저장 완료</strong>: C:\\${SCAN_ROOT_FOLDER_NAME}\\${filename} (선택하신 폴더 기준)</p>
        <ul>
          <li>URL 시트: ${result.urlFindings.length}건</li>
          <li>API-KEY 시트: ${result.apiKeyFindings.length}건</li>
          <li>Scheme 시트: 등록정보 ${result.schemeDefinitions.length}건 + 사용처 ${result.schemeUsages.length}건</li>
        </ul>
      `;
    } catch (e) {
      log(`[!] 오류: ${e.message}`);
      summaryEl.innerHTML = `<p class="status-error">스캔/저장 중 오류가 발생했습니다: ${e.message}</p>`;
    } finally {
      scanBtn.disabled = false;
    }
  });
});
