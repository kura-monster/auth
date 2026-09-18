const fs = require('fs');

const templateCache = new Map();

const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
  '=': '&#61;'
};

const JSON_UNSAFE_CODES = [0x3c, 0x3e, 0x26, 0x2028, 0x2029];

function toUnicodeEscape(codePoint) {
  return '\\u' + codePoint.toString(16).padStart(4, '0');
}

const JSON_UNSAFE = new RegExp(
  '[' + JSON_UNSAFE_CODES.map(toUnicodeEscape).join('') + ']',
  'g'
);

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"'`=]/g, char => HTML_ESCAPES[char]);
}

function escapeJson(value) {
  return JSON.stringify(value === undefined ? null : value)
    .replace(JSON_UNSAFE, char => toUnicodeEscape(char.charCodeAt(0)));
}

function loadTemplate(filePath) {
  if (process.env.NODE_ENV !== 'production') {
    return fs.readFileSync(filePath, 'utf8');
  }
  let cached = templateCache.get(filePath);
  if (!cached) {
    cached = fs.readFileSync(filePath, 'utf8');
    templateCache.set(filePath, cached);
  }
  return cached;
}

function renderTemplate(filePath, data) {
  const source = loadTemplate(filePath);

  return source.replace(/<%(=|json)\s+([A-Za-z0-9_]+)\s*%>/g, (match, mode, key) => {
    if (!Object.prototype.hasOwnProperty.call(data, key)) {
      console.warn(`[Render] テンプレート変数が未指定です: ${key} (${filePath})`);
      return '';
    }
    return mode === 'json' ? escapeJson(data[key]) : escapeHtml(data[key]);
  });
}

module.exports = { renderTemplate, escapeHtml, escapeJson };
