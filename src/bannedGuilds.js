const fs = require('fs');
const path = require('path');

const FILE_PATH = path.join(__dirname, '..', 'banned_guilds.json');
const GUILD_ID_PATTERN = /^\d{17,20}$/;

let cache = null;
let cacheMtimeMs = 0;

function readFromDisk() {
  try {
    if (!fs.existsSync(FILE_PATH)) return [];
    const raw = fs.readFileSync(FILE_PATH, 'utf8');
    const parsed = JSON.parse(raw || '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(id => typeof id === 'string' && GUILD_ID_PATTERN.test(id));
  } catch (error) {
    console.error('[BannedGuilds] 読み込みに失敗しました:', error.message);
    return cache || [];
  }
}

function getBannedGuilds() {
  try {
    const mtimeMs = fs.existsSync(FILE_PATH) ? fs.statSync(FILE_PATH).mtimeMs : 0;
    if (cache && mtimeMs === cacheMtimeMs) return cache;
    cache = readFromDisk();
    cacheMtimeMs = mtimeMs;
    return cache;
  } catch {
    return cache || [];
  }
}

function saveBannedGuilds(guilds) {
  const unique = [...new Set(guilds.filter(id => GUILD_ID_PATTERN.test(id)))];
  const tmpPath = `${FILE_PATH}.${process.pid}.tmp`;

  try {
    fs.writeFileSync(tmpPath, JSON.stringify(unique, null, 2), 'utf8');
    fs.renameSync(tmpPath, FILE_PATH);
    cache = unique;
    cacheMtimeMs = fs.statSync(FILE_PATH).mtimeMs;
    return true;
  } catch (error) {
    console.error('[BannedGuilds] 保存に失敗しました:', error.message);
    try { fs.unlinkSync(tmpPath); } catch {}
    return false;
  }
}

function isValidGuildId(id) {
  return GUILD_ID_PATTERN.test(String(id || '').trim());
}

module.exports = { getBannedGuilds, saveBannedGuilds, isValidGuildId, FILE_PATH };
