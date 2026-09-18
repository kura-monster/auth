const DEFAULT_MAX_ENTRIES = 50000;

class TtlMap {
  constructor(name, maxEntries = DEFAULT_MAX_ENTRIES) {
    this.name = name;
    this.maxEntries = maxEntries;
    this.map = new Map();
  }

  set(key, value, ttlMs) {
    if (this.map.size >= this.maxEntries) {
      this.sweep();
      while (this.map.size >= this.maxEntries) {
        const oldest = this.map.keys().next();
        if (oldest.done) break;
        this.map.delete(oldest.value);
      }
    }
    this.map.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  take(key) {
    const value = this.get(key);
    if (value !== undefined) this.map.delete(key);
    return value;
  }

  delete(key) {
    return this.map.delete(key);
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.map.entries()) {
      if (now > entry.expiresAt) this.map.delete(key);
    }
  }

  get size() {
    return this.map.size;
  }
}

class SlidingWindowLimiter {
  constructor(name, { windowMs, limit, maxKeys = DEFAULT_MAX_ENTRIES }) {
    this.name = name;
    this.windowMs = windowMs;
    this.limit = limit;
    this.maxKeys = maxKeys;
    this.hits = new Map();
  }

  peek(key) {
    const timestamps = this.prune(key);
    return { allowed: timestamps.length < this.limit, remaining: Math.max(0, this.limit - timestamps.length) };
  }

  consume(key) {
    const timestamps = this.prune(key);
    if (timestamps.length >= this.limit) {
      const retryAfterMs = this.windowMs - (Date.now() - timestamps[0]);
      return { allowed: false, remaining: 0, retryAfterMs: Math.max(1000, retryAfterMs) };
    }
    timestamps.push(Date.now());
    if (this.hits.size >= this.maxKeys) this.sweep();
    this.hits.set(key, timestamps);
    return { allowed: true, remaining: this.limit - timestamps.length, retryAfterMs: 0 };
  }

  prune(key) {
    const cutoff = Date.now() - this.windowMs;
    const timestamps = (this.hits.get(key) || []).filter(t => t > cutoff);
    if (timestamps.length === 0) this.hits.delete(key);
    return timestamps;
  }

  sweep() {
    const cutoff = Date.now() - this.windowMs;
    for (const [key, timestamps] of this.hits.entries()) {
      const kept = timestamps.filter(t => t > cutoff);
      if (kept.length === 0) this.hits.delete(key);
      else this.hits.set(key, kept);
    }
  }

  get size() {
    return this.hits.size;
  }
}

const sweepables = [];

function register(instance) {
  sweepables.push(instance);
  return instance;
}

function startSweeper(intervalMs = 60000) {
  const timer = setInterval(() => {
    for (const instance of sweepables) {
      try {
        instance.sweep();
      } catch (err) {
        console.error(`[Security] sweep failed for ${instance.name || 'store'}:`, err.message);
      }
    }
  }, intervalMs);
  timer.unref?.();
  return timer;
}

module.exports = { TtlMap, SlidingWindowLimiter, register, startSweeper };
