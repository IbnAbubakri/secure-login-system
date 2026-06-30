import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

const cache = {};

export function loadJSON(path, fallback) {
  if (cache[path] !== undefined) return cache[path];
  if (!existsSync(path)) { cache[path] = fallback; return fallback; }
  try {
    const data = JSON.parse(readFileSync(path, 'utf-8'));
    cache[path] = data;
    return data;
  } catch {
    cache[path] = fallback;
    return fallback;
  }
}

export function saveJSON(path, data) {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const tmp = path + '.tmp.' + process.pid;
  writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
  renameSync(tmp, path);
  cache[path] = data;
}

export function clearCache(path) {
  if (path) delete cache[path];
  else Object.keys(cache).forEach((k) => delete cache[k]);
}
