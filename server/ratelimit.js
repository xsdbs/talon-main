/**
 * Token-bucket rate limiting.
 *
 * This is a personal relay on a tailnet, not a public API, so the job is to
 * bound accidents and a compromised device rather than to survive a botnet.
 * The limits below are deliberately generous: locking someone out of their own
 * messenger is a worse failure than letting a burst through.
 *
 * A bucket holds `capacity` tokens and refills at `refillPerSec`. Taking a
 * token costs one unit by default; upload byte budgets charge more. Buckets
 * are created lazily and swept, because an unbounded map keyed by attacker
 * input is itself the denial-of-service it was meant to prevent.
 */

const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
const MAX_RETRY_AFTER_SEC = 3600;

export function createLimiter({ capacity, refillPerSec, name = 'limiter' }) {
  const buckets = new Map();

  const bucketFor = (key, now) => {
    let b = buckets.get(key);
    if (!b) {
      b = { tokens: capacity, last: now };
      buckets.set(key, b);
    } else {
      const elapsed = (now - b.last) / 1000;
      b.tokens = Math.min(capacity, b.tokens + elapsed * refillPerSec);
      b.last = now;
    }
    return b;
  };

  return {
    name,

    /** Spends `cost` tokens. Returns true if allowed. */
    take(key, cost = 1, now = Date.now()) {
      if (!key) return true; // nothing to key on; fail open rather than lock out
      const b = bucketFor(String(key), now);
      if (b.tokens < cost) return false;
      b.tokens -= cost;
      return true;
    },

    /** True if `cost` tokens are available, without spending them. */
    allowed(key, cost = 1, now = Date.now()) {
      if (!key) return true;
      return bucketFor(String(key), now).tokens >= cost;
    },

    /**
     * Seconds until `cost` tokens would be available, for Retry-After.
     *
     * Clamped, and never Infinity. A bucket configured with no refill really
     * never does recover, but `Retry-After: Infinity` is not a valid header
     * and a client parsing it gets NaN, so a large finite number is both
     * honest enough and actually usable.
     */
    retryAfter(key, cost = 1, now = Date.now()) {
      const b = bucketFor(String(key), now);
      if (b.tokens >= cost) return 0;
      if (refillPerSec <= 0) return MAX_RETRY_AFTER_SEC;
      return Math.min(MAX_RETRY_AFTER_SEC, Math.ceil((cost - b.tokens) / refillPerSec));
    },

    /** Gives tokens back, for when a request turns out to have been fine. */
    refund(key, cost = 1) {
      const b = buckets.get(String(key));
      if (b) b.tokens = Math.min(capacity, b.tokens + cost);
    },

    /** Drops buckets that have refilled completely; they carry no state. */
    sweep(now = Date.now()) {
      for (const [key, b] of buckets) {
        const elapsed = (now - b.last) / 1000;
        if (b.tokens + elapsed * refillPerSec >= capacity) buckets.delete(key);
      }
    },

    size() { return buckets.size; }
  };
}

/**
 * Starts the periodic sweep for a set of limiters. Unref'd so it never holds
 * the process open on shutdown.
 */
export function startSweeping(limiters) {
  const t = setInterval(() => {
    for (const l of limiters) l.sweep();
  }, SWEEP_INTERVAL_MS);
  if (t.unref) t.unref();
  return t;
}

/**
 * The client address to key on. Behind Tailscale this is the peer's 100.x
 * address, which is exactly the granularity wanted. X-Forwarded-For is
 * deliberately ignored: nothing is supposed to be in front of this relay, and
 * trusting a client-supplied header would let anyone reset their own bucket by
 * inventing an address.
 */
export function clientKey(req) {
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}
