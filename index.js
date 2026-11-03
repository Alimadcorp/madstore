require('dotenv').config({ quiet: true })

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const http = require('http')
const { promisify } = require('util')
const { Redis } = require('ioredis')
const { WebSocketServer } = require('ws')

const scrypt = promisify(crypto.scrypt)
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

// ---------------------------------------------------------------- config

const ON_RAILWAY = Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_PROJECT_ID)
const SOCKET_ENABLED = (process.env.SOCKET_MODE ?? '1') === '1'
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*'
const TRUST_PROXY = process.env.TRUST_PROXY !== undefined ? process.env.TRUST_PROXY === '1' : ON_RAILWAY
const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_PUBLIC_URL
const PREFIX = process.env.REDIS_PREFIX || 'madstore:'

const MAX_BODY = 1024 * 1024
const MAX_DOC_BYTES = 8 * 1024 * 1024
const MAX_SECRET_LENGTH = 256
const MAX_PATH_LENGTH = 512
const MAX_SUBS = 10
const MAX_TS_SKEW = 5 * 60 * 1000
const MAX_VALUE_NESTING = 100
const MAX_WS_QUEUE = 50
const LOCK_TTL_MS = 10000
const LOCK_WAIT_MS = 5000
const KEY_PATTERN = /^[A-Za-z0-9_-]{1,64}$/
const OPS = new Set(['create', 'password', 'get', 'set', 'upsert', 'delete'])
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'))

if (!REDIS_URL) throw new Error('REDIS_URL is not set')

// ---------------------------------------------------------------- redis

// family: 0 lets the client use IPv4 or IPv6 (Railway private networking can be IPv6-only).
const redis = new Redis(REDIS_URL, { family: 0, maxRetriesPerRequest: 3 })
redis.on('error', (e) => console.error('Redis error:', e.message))

const subscriber = SOCKET_ENABLED ? redis.duplicate() : null
if (subscriber) subscriber.on('error', (e) => console.error('Redis subscriber error:', e.message))

const kMeta = (key) => `${PREFIX}meta:${key}`
const kData = (key) => `${PREFIX}data:${key}`
const kLock = (key) => `${PREFIX}lock:${key}`
const kChan = (key) => `${PREFIX}chg:${key}`

const RELEASE_LOCK = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"

function httpError (status, message) {
  return Object.assign(new Error(message), { status })
}

// Per-key mutex across processes, so read-modify-write on a key's document is atomic.
async function withLock (key, fn) {
  const lockKey = kLock(key)
  const token = crypto.randomBytes(12).toString('hex')
  const deadline = Date.now() + LOCK_WAIT_MS
  for (;;) {
    const ok = await redis.set(lockKey, token, 'PX', LOCK_TTL_MS, 'NX')
    if (ok === 'OK') break
    if (Date.now() > deadline) throw httpError(503, 'Key is busy, try again')
    await sleep(15 + Math.random() * 25)
  }
  try {
    return await fn()
  } finally {
    await redis.eval(RELEASE_LOCK, 1, lockKey, token).catch(() => {})
  }
}

async function loadMeta (key) {
  const raw = await redis.get(kMeta(key))
  return raw ? JSON.parse(raw) : null
}

async function execMulti (multi) {
  const results = await multi.exec()
  for (const [err] of results || []) if (err) throw err
}

// ---------------------------------------------------------------- secrets

async function hashSecret (secret) {
  const salt = crypto.randomBytes(16)
  const hash = await scrypt(secret, salt, 32)
  return `s1$${salt.toString('hex')}$${hash.toString('hex')}`
}

async function checkSecret (input, stored) {
  if (typeof input !== 'string' || input.length === 0 || input.length > MAX_SECRET_LENGTH) return false
  if (typeof stored !== 'string') return false
  const [tag, saltHex, hashHex] = stored.split('$')
  if (tag !== 's1' || !saltHex || !hashHex) return false
  const expected = Buffer.from(hashHex, 'hex')
  const actual = await scrypt(input, Buffer.from(saltHex, 'hex'), expected.length)
  return crypto.timingSafeEqual(actual, expected)
}

function validSecret (value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_SECRET_LENGTH
}

// Lazy, memoised checks so we only pay for scrypt when it is actually needed.
function makeAuth (query, meta) {
  let masterP
  const master = () => (masterP ??= checkSecret(query.master, meta.master))
  return {
    master,
    async canRead () { return !meta.read || (await master()) || checkSecret(query.read, meta.read) },
    async canWrite () { return !meta.write || (await master()) || checkSecret(query.write, meta.write) }
  }
}

function validKey (key) {
  return typeof key === 'string' && KEY_PATTERN.test(key)
}

// ---------------------------------------------------------------- paths & documents

function sanitize (p) {
  if (p === undefined || p === null || p === '') return '/'
  if (typeof p !== 'string' || p.length > MAX_PATH_LENGTH) return null
  const parts = p
    .split('/')
    .filter(Boolean)
    .map(s => s.replace(/[.#$\[\]\u0000-\u001f\u007f]/g, '_'))
    .map(s => (s === '__proto__' ? '_proto_' : s))
  return parts.length ? `/${parts.join('/')}` : '/'
}

const toSegments = (cleanPath) => (cleanPath === '/' ? [] : cleanPath.split('/').filter(Boolean))

function withinDepth (cleanPath, max) {
  return toSegments(cleanPath).length <= max
}

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isEmptyContainer = (v) => v !== null && typeof v === 'object' && Object.keys(v).length === 0

function safeValue (v, depth = 0) {
  if (v === null || typeof v !== 'object') return true
  if (depth > MAX_VALUE_NESTING) return false
  if (Array.isArray(v)) return v.every(x => safeValue(x, depth + 1))
  for (const k of Object.keys(v)) {
    if (k === '__proto__') return false
    if (!safeValue(v[k], depth + 1)) return false
  }
  return true
}

function getAt (doc, segs) {
  let cur = doc
  for (const s of segs) {
    if (cur !== null && typeof cur === 'object' && has(cur, s)) cur = cur[s]
    else return null
  }
  return cur === undefined ? null : cur
}

// Writes along a path turn arrays into objects with numeric keys (like Firebase did).
function setAt (doc, segs, value) {
  if (!segs.length) return value
  const root = isObj(doc) ? { ...doc } : Array.isArray(doc) ? Object.assign({}, doc) : {}
  let cur = root
  for (let i = 0; i < segs.length - 1; i++) {
    const s = segs[i]
    let next = has(cur, s) ? cur[s] : undefined
    if (Array.isArray(next)) next = Object.assign({}, next)
    else if (isObj(next)) next = { ...next }
    else next = {}
    cur[s] = next
    cur = next
  }
  cur[segs[segs.length - 1]] = value
  return root
}

// Removes a path and prunes parents that become empty. Returns null when nothing is left.
function deleteAt (doc, segs) {
  if (!segs.length) return null
  if (doc === null || typeof doc !== 'object') return doc
  const [head, ...rest] = segs
  if (!has(doc, head)) return doc
  const obj = Array.isArray(doc) ? Object.assign({}, doc) : { ...doc }
  if (rest.length) {
    const child = deleteAt(obj[head], rest)
    if (child === null || (typeof child === 'object' && Object.keys(child).length === 0)) delete obj[head]
    else obj[head] = child
  } else {
    delete obj[head]
  }
  return Object.keys(obj).length ? obj : null
}

// ---------------------------------------------------------------- rate limiting

function makeLimiter (max, windowMs) {
  const entries = new Map()
  setInterval(() => {
    const now = Date.now()
    for (const [id, e] of entries) if (e.reset < now) entries.delete(id)
  }, windowMs).unref()
  return {
    blocked (id) {
      const e = entries.get(id)
      return Boolean(e) && e.reset >= Date.now() && e.count >= max
    },
    add (id) {
      const now = Date.now()
      let e = entries.get(id)
      if (!e || e.reset < now) {
        e = { count: 0, reset: now + windowMs }
        entries.set(id, e)
      }
      e.count++
    }
  }
}

const requestLimiter = makeLimiter(120, 60000)
const failureLimiter = makeLimiter(15, 60000)

function clientIp (req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers['x-forwarded-for']
    if (typeof forwarded === 'string' && forwarded) return forwarded.split(',')[0].trim()
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown'
}

// ---------------------------------------------------------------- subscriptions (WebSocket)

const keySubs = new Map() // key -> Set<sub>
const refreshState = new Map() // key -> { running, pending }

function addSub (ws, sub) {
  ws.subscriptions.push(sub)
  let set = keySubs.get(sub.key)
  if (!set) {
    set = new Set()
    keySubs.set(sub.key, set)
    subscriber.subscribe(kChan(sub.key)).catch(e => console.error('Subscribe error:', e.message))
  }
  set.add(sub)
  refresh(sub.key)
}

function clearSubs (ws) {
  for (const sub of ws.subscriptions || []) {
    const set = keySubs.get(sub.key)
    if (!set) continue
    set.delete(sub)
    if (!set.size) {
      keySubs.delete(sub.key)
      subscriber.unsubscribe(kChan(sub.key)).catch(() => {})
    }
  }
  ws.subscriptions = []
}

// Reads the document once and pushes to every subscriber whose path changed.
// Coalesced per key so bursts of writes never deliver stale data after fresh data.
function refresh (key) {
  let st = refreshState.get(key)
  if (!st) {
    st = { running: false, pending: false }
    refreshState.set(key, st)
  }
  if (st.running) {
    st.pending = true
    return
  }
  st.running = true
  ;(async () => {
    try {
      do {
        st.pending = false
        const subs = keySubs.get(key)
        if (!subs || !subs.size) break
        const raw = await redis.get(kData(key))
        const doc = raw === null ? null : JSON.parse(raw)
        for (const sub of [...subs]) {
          const data = getAt(doc, sub.segs)
          const serialized = JSON.stringify(data)
          if (serialized === sub.last) continue
          sub.last = serialized
          if (sub.ws.readyState === 1) {
            sub.ws.send(JSON.stringify({ type: 'update', key, path: sub.path, data, ts: Date.now() }))
          }
        }
      } while (st.pending)
    } catch (e) {
      console.error('Refresh error:', e.message)
    } finally {
      st.running = false
      if (!keySubs.has(key)) refreshState.delete(key)
    }
  })()
}

if (subscriber) {
  const chanPrefix = `${PREFIX}chg:`
  subscriber.on('message', (chan) => {
    const key = chan.slice(chanPrefix.length)
    if (keySubs.has(key)) refresh(key)
  })
  // After a reconnect we may have missed notifications.
  subscriber.on('ready', () => { for (const key of keySubs.keys()) refresh(key) })
}

async function subscribeOp (query, ws, ts) {
  if (!SOCKET_ENABLED) return { status: 400, json: { error: 'WebSocket is disabled', ts } }
  if (!ws) return { status: 400, json: { error: 'Subscribe is only available via WebSocket', ts } }
  const keys = query.keys
  if (!Array.isArray(keys) || keys.length > MAX_SUBS) {
    return { status: 400, json: { error: `keys must be an array of at most ${MAX_SUBS}`, ts } }
  }

  clearSubs(ws)

  const results = []
  const accepted = []
  for (const item of keys) {
    const entry = typeof item === 'string' ? { key: item } : item
    if (!entry || typeof entry !== 'object' || !validKey(entry.key)) {
      results.push({ error: 'Invalid key' })
      continue
    }
    const key = entry.key
    const meta = await loadMeta(key)
    if (!meta) {
      results.push({ key, error: 'Key not found' })
      continue
    }
    const cleanPath = sanitize(entry.path)
    if (cleanPath === null || !withinDepth(cleanPath, meta.depth || 5)) {
      results.push({ key, error: 'Invalid path' })
      continue
    }
    if (!(await makeAuth(entry, meta).canRead())) {
      results.push({ key, error: 'Invalid read password' })
      continue
    }
    accepted.push({ ws, key, path: cleanPath, segs: toSegments(cleanPath), last: undefined })
    results.push({ key, path: cleanPath, status: 'subscribed' })
  }

  // The socket may have closed while we were awaiting; do not leak subscriptions.
  if (ws.readyState !== 1) return { status: 400, json: { error: 'Socket closed', ts } }
  for (const sub of accepted) addSub(ws, sub)
  return { status: 200, json: { message: 'Subscribed', results, ts } }
}

// ---------------------------------------------------------------- operations

// Runs mutator(doc) under the key lock and stores the result atomically with meta.lastTs.
async function commit (key, authMeta, ts, mutator) {
  return withLock(key, async () => {
    const meta = await loadMeta(key)
    if (!meta) return { status: 404, json: { error: 'Key not found', ts } }
    if (meta.master !== authMeta.master || meta.read !== authMeta.read || meta.write !== authMeta.write) {
      return { status: 403, json: { error: 'Credentials changed, retry', ts } }
    }
    if (ts !== undefined && meta.lastTs && ts < meta.lastTs) {
      return { status: 409, json: { error: 'Operation rejected: ts is older than lastTs', ts, lastTs: meta.lastTs } }
    }

    const raw = await redis.get(kData(key))
    const doc = raw === null ? null : JSON.parse(raw)
    const newDoc = mutator(doc)
    const json = newDoc === null || newDoc === undefined ? null : JSON.stringify(newDoc)
    if (json !== null && Buffer.byteLength(json) > MAX_DOC_BYTES) {
      return { status: 413, json: { error: 'Stored data for this key would be too large', ts } }
    }

    const multi = redis.multi()
    if (json === null) multi.del(kData(key))
    else multi.set(kData(key), json)
    if (ts !== undefined) {
      meta.lastTs = ts
      multi.set(kMeta(key), JSON.stringify(meta))
    }
    multi.publish(kChan(key), '1')
    await execMulti(multi)
    return null
  })
}

async function createOp (query, ts) {
  const key = query.key
  if (!validSecret(query.master)) {
    return { status: 400, json: { error: 'Master password required', ts } }
  }
  for (const field of ['read', 'write']) {
    const v = query[field]
    if (v !== undefined && v !== null && v !== '' && !validSecret(v)) {
      return { status: 400, json: { error: `Invalid ${field} password`, ts } }
    }
  }
  const depthValue = query.depth === undefined || query.depth === '' ? 5 : Number(query.depth)
  if (!Number.isInteger(depthValue) || depthValue < 1 || depthValue > 20) {
    return { status: 400, json: { error: 'depth must be an integer between 1 and 20', ts } }
  }

  const meta = {
    master: await hashSecret(query.master),
    read: query.read ? await hashSecret(query.read) : null,
    write: query.write ? await hashSecret(query.write) : null,
    depth: depthValue,
    created: Date.now(),
    lastTs: ts || null
  }

  const ok = await redis.set(kMeta(key), JSON.stringify(meta), 'NX')
  if (ok !== 'OK') return { status: 409, json: { error: 'Key already exists', ts } }
  return { status: 201, json: { message: 'Key created', ts } }
}

async function passwordOp (key, query, meta, auth, ts) {
  if (!(await auth.master())) return { status: 403, json: { error: 'Invalid master password', ts } }

  const updates = {}
  if (query.new_master !== undefined && query.new_master !== null && query.new_master !== '') {
    if (!validSecret(query.new_master)) return { status: 400, json: { error: 'Invalid new master password', ts } }
    updates.master = await hashSecret(query.new_master)
  }
  for (const field of ['read', 'write']) {
    const v = query[`new_${field}`]
    if (v === undefined) continue
    if (v !== null && v !== '' && !validSecret(v)) {
      return { status: 400, json: { error: `Invalid new ${field} password`, ts } }
    }
    updates[field] = v ? await hashSecret(v) : null
  }

  const denied = await withLock(key, async () => {
    const current = await loadMeta(key)
    if (!current) return { status: 404, json: { error: 'Key not found', ts } }
    if (current.master !== meta.master) return { status: 403, json: { error: 'Credentials changed, retry', ts } }
    if (ts !== undefined && current.lastTs && ts < current.lastTs) {
      return { status: 409, json: { error: 'Operation rejected: ts is older than lastTs', ts, lastTs: current.lastTs } }
    }
    if (ts !== undefined) updates.lastTs = ts
    if (Object.keys(updates).length > 0) {
      await redis.set(kMeta(key), JSON.stringify({ ...current, ...updates }))
    }
    return null
  })
  if (denied) return denied
  return { status: 200, json: { message: 'Password(s) and metadata updated successfully', ts } }
}

async function deleteKeyOp (key, meta, ts) {
  return withLock(key, async () => {
    const current = await loadMeta(key)
    if (!current) return { status: 404, json: { error: 'Key not found', ts } }
    if (current.master !== meta.master) return { status: 403, json: { error: 'Credentials changed, retry', ts } }
    await execMulti(redis.multi().del(kData(key)).del(kMeta(key)).publish(kChan(key), '1'))
    return { status: 200, json: { message: 'Key deleted', ts } }
  })
}

async function operate (opType, query, wsClient = null) {
  let ts
  if (query.ts !== undefined && query.ts !== null && query.ts !== '') {
    ts = Number(query.ts)
    if (!Number.isSafeInteger(ts) || ts < 0 || ts > Date.now() + MAX_TS_SKEW) {
      return { status: 400, json: { error: 'Invalid ts' } }
    }
  }

  if (opType === 'subscribe') return subscribeOp(query, wsClient, ts)

  const key = query.key
  if (!validKey(key)) {
    return { status: 400, json: { error: 'Missing or invalid key (1-64 chars: letters, digits, _ or -)', ts } }
  }

  if (opType === 'create') return createOp(query, ts)

  const meta = await loadMeta(key)
  if (!meta) return { status: 404, json: { error: 'Key not found', ts } }
  const auth = makeAuth(query, meta)

  if (opType === 'password') return passwordOp(key, query, meta, auth, ts)

  const cleanPath = sanitize(query.path)
  if (cleanPath === null) return { status: 400, json: { error: 'Invalid path', ts } }
  if (!withinDepth(cleanPath, meta.depth || 5)) {
    return { status: 403, json: { error: `Path exceeds max depth of ${meta.depth || 5}`, ts } }
  }
  const segs = toSegments(cleanPath)

  if (opType === 'get') {
    if (!(await auth.canRead())) return { status: 403, json: { error: 'Invalid read password', ts } }
    const raw = await redis.get(kData(key))
    const data = raw === null ? null : getAt(JSON.parse(raw), segs)
    return { status: 200, json: { path: cleanPath, data, ts } }
  }

  if (opType === 'set' || opType === 'upsert') {
    if (!(await auth.canWrite())) return { status: 403, json: { error: 'Invalid write password', ts } }
    if (query.value === undefined || query.value === null) {
      return { status: 400, json: { error: 'Missing value parameter', ts } }
    }

    let parsed = query.value
    if (typeof parsed === 'string') {
      try { parsed = JSON.parse(parsed) } catch (e) {
        if (opType === 'upsert') return { status: 400, json: { error: 'Upsert value must be a JSON object', ts } }
      }
    }
    if (parsed === null || parsed === undefined || !safeValue(parsed)) {
      return { status: 400, json: { error: 'Invalid data', ts } }
    }

    let mutator
    if (opType === 'set') {
      mutator = (doc) => (isEmptyContainer(parsed) ? deleteAt(doc, segs) : setAt(doc, segs, parsed))
    } else {
      if (!isObj(parsed) || Object.keys(parsed).some(k => k.includes('/'))) {
        return { status: 400, json: { error: 'Upsert value must be a flat JSON object without "/" in keys', ts } }
      }
      mutator = (doc) => {
        const existing = getAt(doc, segs)
        const target = isObj(existing) ? { ...existing } : Array.isArray(existing) ? Object.assign({}, existing) : {}
        for (const [k, v] of Object.entries(parsed)) {
          if (v === null) delete target[k]
          else target[k] = v
        }
        return Object.keys(target).length ? setAt(doc, segs, target) : deleteAt(doc, segs)
      }
    }

    const failure = await commit(key, meta, ts, mutator)
    if (failure) return failure
    return {
      status: 200,
      json: { message: opType === 'set' ? 'Data set successfully' : 'Data upserted successfully', path: cleanPath, ts }
    }
  }

  if (opType === 'delete') {
    if (cleanPath === '/') {
      if (!(await auth.master())) return { status: 403, json: { error: 'Master password required to delete entire key', ts } }
      return deleteKeyOp(key, meta, ts)
    }
    if (!(await auth.canWrite())) return { status: 403, json: { error: 'Invalid write password', ts } }
    const failure = await commit(key, meta, ts, (doc) => deleteAt(doc, segs))
    if (failure) return failure
    return { status: 200, json: { message: 'Path deleted successfully', path: cleanPath, ts } }
  }

  return { status: 400, json: { error: 'Unknown operation', ts } }
}

async function guarded (opType, query, ip, wsClient = null) {
  if (requestLimiter.blocked(ip) || failureLimiter.blocked(ip)) {
    return { status: 429, json: { error: 'Too many requests' } }
  }
  requestLimiter.add(ip)
  const result = await operate(opType, query, wsClient)
  const failed = result.status === 403 || result.status === 404 ||
    (opType === 'subscribe' && Array.isArray(result.json.results) && result.json.results.some(r => r.error))
  if (failed) failureLimiter.add(ip)
  return result
}

// ---------------------------------------------------------------- HTTP

const parseBody = (req) => new Promise((resolve, reject) => {
  const chunks = []
  let size = 0
  let tooLarge = false
  req.on('data', chunk => {
    size += chunk.length
    if (size > MAX_BODY) tooLarge = true
    else chunks.push(chunk)
  })
  req.on('end', () => {
    if (tooLarge) return reject(httpError(413, 'Payload too large'))
    try {
      const text = Buffer.concat(chunks).toString('utf8')
      const parsed = text ? JSON.parse(text) : {}
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return reject(httpError(400, 'Body must be a JSON object'))
      }
      resolve(parsed)
    } catch (e) {
      reject(httpError(400, 'Invalid JSON body'))
    }
  })
  req.on('error', reject)
})

const SECRET_HEADERS = { master: 'x-master', read: 'x-read', write: 'x-write' }

const handler = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN)
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Master, X-Read, X-Write')
  res.setHeader('Vary', 'Origin')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Frame-Options', 'DENY')

  if (!res.status) res.status = (code) => { res.statusCode = code; return res }
  if (!res.json) res.json = (data) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(data)) }
  if (!res.send) res.send = (data) => { res.end(data) }

  if (req.method === 'OPTIONS') {
    res.statusCode = 204
    return res.end()
  }

  let url
  try {
    url = new URL(req.url, 'http://localhost')
  } catch (e) {
    return res.status(400).json({ error: 'Bad request' })
  }
  const pathname = url.pathname

  if (pathname === '/' || pathname === '/index.html') {
    if (req.method !== 'GET' && req.method !== 'HEAD') return res.status(405).json({ error: 'Method not allowed' })
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    return res.status(200).send(req.method === 'HEAD' ? undefined : INDEX_HTML)
  }

  res.setHeader('Cache-Control', 'no-store')

  if (pathname === '/health') {
    try {
      await redis.ping()
      return res.status(200).json({ ok: true })
    } catch (e) {
      return res.status(503).json({ ok: false })
    }
  }

  if (pathname === '/config') {
    return res.status(200).json({ socket: SOCKET_ENABLED })
  }

  if (pathname === '/socket') {
    if (!SOCKET_ENABLED) return res.status(404).json({ error: 'WebSocket is disabled' })
    return res.status(426).send('Upgrade Required')
  }

  let opType = pathname.replace(/^\/+/, '')
  if (req.method === 'DELETE') opType = 'delete'
  if (req.method === 'PUT' || req.method === 'PATCH') opType = 'upsert'

  if (!OPS.has(opType)) return res.status(404).json({ error: 'Not found' })
  if ((req.method === 'GET' || req.method === 'HEAD') && opType !== 'get') {
    return res.status(405).json({ error: 'Method not allowed' })
  }
  if (opType === 'create' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  let bodyParams = {}
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    try {
      bodyParams = await parseBody(req)
    } catch (e) {
      return res.status(e.status || 400).json({ error: e.message })
    }
  }

  const query = { ...bodyParams }
  for (const field of ['key', 'path', 'ts', 'depth']) {
    if (url.searchParams.has(field)) query[field] = url.searchParams.get(field)
  }
  for (const [field, header] of Object.entries(SECRET_HEADERS)) {
    if (typeof req.headers[header] === 'string') query[field] = req.headers[header]
  }

  try {
    const result = await guarded(opType, query, clientIp(req))
    return res.status(result.status).json(result.json)
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message })
    console.error('Server Error:', error)
    return res.status(500).json({ error: 'Internal Server Error' })
  }
}

module.exports = handler

// ---------------------------------------------------------------- server

if (require.main === module) {
  const PORT = process.env.PORT || 3000
  const server = http.createServer(handler)
  let heartbeat

  if (SOCKET_ENABLED) {
    const wss = new WebSocketServer({ server, path: '/socket', maxPayload: MAX_BODY })

    wss.on('connection', (ws, req) => {
      ws.subscriptions = []
      ws.isAlive = true
      ws.queue = Promise.resolve()
      ws.queued = 0
      const ip = clientIp(req)
      const reply = (data) => { if (ws.readyState === 1) ws.send(JSON.stringify(data)) }

      ws.on('pong', () => { ws.isAlive = true })

      const handle = async (message) => {
        let payload
        try {
          payload = JSON.parse(message.toString())
        } catch (e) {
          return reply({ error: 'Invalid WebSocket message format' })
        }
        if (!payload || typeof payload !== 'object' || typeof payload.type !== 'string') {
          return reply({ error: 'Invalid WebSocket message format' })
        }
        const type = payload.type
        if (type !== 'subscribe' && !OPS.has(type)) return reply({ error: 'Unknown operation' })

        const body = payload.body && typeof payload.body === 'object' && !Array.isArray(payload.body) ? payload.body : {}
        const query = { ...body, ts: payload.ts !== undefined ? payload.ts : body.ts }

        try {
          const result = await guarded(type, query, ip, ws)
          reply({ op: type, status: result.status, ...result.json })
        } catch (e) {
          if (e.status) return reply({ op: type, status: e.status, error: e.message })
          console.error('Socket Error:', e)
          reply({ op: type, status: 500, error: 'Internal Server Error' })
        }
      }

      // Messages from one connection are processed in order (subscribe replaces earlier subscriptions).
      ws.on('message', (message) => {
        if (ws.queued >= MAX_WS_QUEUE) return reply({ status: 429, error: 'Too many pending messages' })
        ws.queued++
        ws.queue = ws.queue.then(() => handle(message)).catch(() => {}).finally(() => { ws.queued-- })
      })

      ws.on('close', () => clearSubs(ws))
      ws.on('error', () => clearSubs(ws))
    })

    heartbeat = setInterval(() => {
      for (const ws of wss.clients) {
        if (!ws.isAlive) { ws.terminate(); continue }
        ws.isAlive = false
        ws.ping()
      }
    }, 30000)
    heartbeat.unref()
  }

  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT} (WebSocket ${SOCKET_ENABLED ? 'on' : 'off'}, Redis prefix "${PREFIX}")`)
  })

  const shutdown = () => {
    server.close()
    Promise.allSettled([redis.quit(), subscriber ? subscriber.quit() : null]).finally(() => process.exit(0))
    setTimeout(() => process.exit(0), 5000).unref()
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}
