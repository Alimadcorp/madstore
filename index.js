require('dotenv').config({ quiet: true })

const https = require('https')
https.globalAgent.options.family = 4

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { promisify } = require('util')
const { initializeApp, getApps, cert } = require('firebase-admin/app')
const { getDatabase } = require('firebase-admin/database')
const { WebSocketServer } = require('ws')

const scrypt = promisify(crypto.scrypt)

const SOCKET_ENABLED = (process.env.SOCKET_MODE ?? (process.env.VERCEL ? '0' : '1')) === '1'
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*'
const TRUST_PROXY = Boolean(process.env.VERCEL) || process.env.TRUST_PROXY === '1'
const MAX_BODY = 1024 * 1024
const MAX_SECRET_LENGTH = 256
const MAX_PATH_LENGTH = 512
const MAX_SUBS = 10
const MAX_TS_SKEW = 5 * 60 * 1000
const KEY_PATTERN = /^[A-Za-z0-9_-]{1,64}$/
const OPS = new Set(['create', 'password', 'get', 'set', 'upsert', 'delete'])
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'))

function loadCredential () {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT
  if (raw) {
    const text = raw.trim().startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8')
    return cert(JSON.parse(text))
  }
  const certPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || path.resolve(__dirname, 'rtdb.json')
  if (fs.existsSync(certPath)) return cert(certPath)
  return undefined
}

if (!getApps().length) {
  if (!process.env.FIREBASE_DATABASE_URL) throw new Error('FIREBASE_DATABASE_URL is not set')
  initializeApp({
    credential: loadCredential(),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  })
}
const db = getDatabase()

async function hashSecret (secret) {
  const salt = crypto.randomBytes(16)
  const hash = await scrypt(secret, salt, 32)
  return `s1$${salt.toString('hex')}$${hash.toString('hex')}`
}

async function checkSecret (input, stored) {
  if (typeof input !== 'string' || typeof stored !== 'string') return false
  if (input.length > MAX_SECRET_LENGTH) return false
  if (stored.startsWith('s1$')) {
    const [, saltHex, hashHex] = stored.split('$')
    const expected = Buffer.from(hashHex, 'hex')
    const actual = await scrypt(input, Buffer.from(saltHex, 'hex'), expected.length)
    return crypto.timingSafeEqual(actual, expected)
  }
  const a = crypto.createHash('sha256').update(input).digest()
  const b = crypto.createHash('sha256').update(stored).digest()
  return crypto.timingSafeEqual(a, b)
}

function validSecret (value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_SECRET_LENGTH
}

function validKey (key) {
  return typeof key === 'string' && KEY_PATTERN.test(key)
}

function sanitize (p) {
  if (p === undefined || p === null || p === '') return '/'
  if (typeof p !== 'string' || p.length > MAX_PATH_LENGTH) return null
  const parts = p
    .split('/')
    .filter(Boolean)
    .map(s => s.replace(/[.#$\[\]\u0000-\u001f\u007f]/g, '_'))
  return parts.length ? `/${parts.join('/')}` : '/'
}

function withinDepth (cleanPath, max) {
  if (cleanPath === '/') return true
  return cleanPath.split('/').filter(Boolean).length <= max
}

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

function clearSubs (wsClient) {
  for (const sub of wsClient.subscriptions || []) sub.ref.off('value', sub.callback)
  wsClient.subscriptions = []
}

async function operate (opType, query, wsClient = null) {
  let ts
  if (query.ts !== undefined && query.ts !== null && query.ts !== '') {
    ts = Number(query.ts)
    if (!Number.isSafeInteger(ts) || ts < 0 || ts > Date.now() + MAX_TS_SKEW) {
      return { status: 400, json: { error: 'Invalid ts' } }
    }
  }

  if (opType === 'subscribe') {
    if (!SOCKET_ENABLED) return { status: 400, json: { error: 'WebSocket is disabled', ts } }
    if (!wsClient) return { status: 400, json: { error: 'Subscribe is only available via WebSocket', ts } }
    const keys = query.keys
    if (!Array.isArray(keys) || keys.length > MAX_SUBS) {
      return { status: 400, json: { error: `keys must be an array of at most ${MAX_SUBS}`, ts } }
    }

    clearSubs(wsClient)

    const results = []
    for (const item of keys) {
      const entry = typeof item === 'string' ? { key: item } : item
      if (!entry || typeof entry !== 'object' || !validKey(entry.key)) {
        results.push({ error: 'Invalid key' })
        continue
      }
      const key = entry.key

      const metaSnap = await db.ref(`metadata/${key}`).once('value')
      if (!metaSnap.exists()) {
        results.push({ key, error: 'Key not found' })
        continue
      }

      const meta = metaSnap.val()
      const cleanPath = sanitize(entry.path)
      if (cleanPath === null || !withinDepth(cleanPath, meta.depth || 5)) {
        results.push({ key, error: 'Invalid path' })
        continue
      }

      const hasMaster = await checkSecret(entry.master, meta.master)
      if (!hasMaster && meta.read && !(await checkSecret(entry.read, meta.read))) {
        results.push({ key, error: 'Invalid read password' })
        continue
      }

      const targetRef = cleanPath === '/' ? db.ref(`data/${key}`) : db.ref(`data/${key}`).child(cleanPath)
      const callback = targetRef.on('value', (snap) => {
        if (wsClient.readyState === 1) {
          wsClient.send(JSON.stringify({ type: 'update', key, path: cleanPath, data: snap.val(), ts: Date.now() }))
        }
      }, () => {})

      wsClient.subscriptions.push({ ref: targetRef, callback })
      results.push({ key, path: cleanPath, status: 'subscribed' })
    }
    return { status: 200, json: { message: 'Subscribed', results, ts } }
  }

  const key = query.key
  if (!validKey(key)) {
    return { status: 400, json: { error: 'Missing or invalid key (1-64 chars: letters, digits, _ or -)', ts } }
  }

  const metaRef = db.ref(`metadata/${key}`)
  const dataRef = db.ref(`data/${key}`)
  const metaUpdates = {}

  if (opType === 'create') {
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

    const tx = await metaRef.transaction(current => (current === null ? meta : undefined))
    if (!tx.committed) return { status: 409, json: { error: 'Key already exists', ts } }
    return { status: 201, json: { message: 'Key created', ts } }
  }

  const metaSnap = await metaRef.once('value')
  if (!metaSnap.exists()) return { status: 404, json: { error: 'Key not found', ts } }

  const meta = metaSnap.val()
  const hasMaster = await checkSecret(query.master, meta.master)
  const readAllowed = async () => hasMaster || !meta.read || checkSecret(query.read, meta.read)
  const writeAllowed = async () => hasMaster || !meta.write || checkSecret(query.write, meta.write)

  const staleTs = () => {
    if (ts !== undefined && meta.lastTs && ts < meta.lastTs) {
      return { status: 409, json: { error: 'Operation rejected: ts is older than lastTs', ts, lastTs: meta.lastTs } }
    }
    if (ts !== undefined) metaUpdates.lastTs = ts
    return null
  }

  if (opType === 'password') {
    if (!hasMaster) return { status: 403, json: { error: 'Invalid master password', ts } }
    const stale = ts !== undefined ? staleTs() : null
    if (stale) return stale

    if (query.new_master !== undefined && query.new_master !== '') {
      if (!validSecret(query.new_master)) return { status: 400, json: { error: 'Invalid new master password', ts } }
      metaUpdates.master = await hashSecret(query.new_master)
    }
    for (const field of ['read', 'write']) {
      const v = query[`new_${field}`]
      if (v === undefined) continue
      if (v !== null && v !== '' && !validSecret(v)) return { status: 400, json: { error: `Invalid new ${field} password`, ts } }
      metaUpdates[field] = v ? await hashSecret(v) : null
    }

    if (Object.keys(metaUpdates).length > 0) await metaRef.update(metaUpdates)
    return { status: 200, json: { message: 'Password(s) and metadata updated successfully', ts } }
  }

  const cleanPath = sanitize(query.path)
  if (cleanPath === null) return { status: 400, json: { error: 'Invalid path', ts } }
  if (!withinDepth(cleanPath, meta.depth || 5)) {
    return { status: 403, json: { error: `Path exceeds max depth of ${meta.depth || 5}`, ts } }
  }

  const targetRef = cleanPath === '/' ? dataRef : dataRef.child(cleanPath)

  if (opType === 'get') {
    if (!(await readAllowed())) return { status: 403, json: { error: 'Invalid read password', ts } }
    const dataSnap = await targetRef.once('value')
    return { status: 200, json: { path: cleanPath, data: dataSnap.val(), ts } }
  }

  if (opType === 'set' || opType === 'upsert') {
    if (!(await writeAllowed())) return { status: 403, json: { error: 'Invalid write password', ts } }
    const stale = staleTs()
    if (stale) return stale
    if (query.value === undefined || query.value === null) {
      return { status: 400, json: { error: 'Missing value parameter', ts } }
    }

    let parsed = query.value
    if (typeof parsed === 'string') {
      try { parsed = JSON.parse(parsed) } catch (e) {
        if (opType === 'upsert') return { status: 400, json: { error: 'Upsert value must be a JSON object', ts } }
      }
    }

    try {
      if (opType === 'set') {
        await targetRef.set(parsed)
      } else {
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).some(k => k.includes('/'))) {
          return { status: 400, json: { error: 'Upsert value must be a flat JSON object without "/" in keys', ts } }
        }
        await targetRef.update(parsed)
      }
    } catch (e) {
      return { status: 400, json: { error: 'Invalid data', ts } }
    }

    await metaRef.update(metaUpdates)
    return {
      status: 200,
      json: { message: opType === 'set' ? 'Data set successfully' : 'Data upserted successfully', path: cleanPath, ts }
    }
  }

  if (opType === 'delete') {
    if (cleanPath === '/') {
      if (!hasMaster) return { status: 403, json: { error: 'Master password required to delete entire key', ts } }
      await targetRef.remove()
      await metaRef.remove()
      return { status: 200, json: { message: 'Key deleted', ts } }
    }
    if (!(await writeAllowed())) return { status: 403, json: { error: 'Invalid write password', ts } }
    const stale = staleTs()
    if (stale) return stale
    await targetRef.remove()
    await metaRef.update(metaUpdates)
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
    if (tooLarge) return reject(Object.assign(new Error('Payload too large'), { status: 413 }))
    try {
      const text = Buffer.concat(chunks).toString('utf8')
      const parsed = text ? JSON.parse(text) : {}
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return reject(Object.assign(new Error('Body must be a JSON object'), { status: 400 }))
      }
      resolve(parsed)
    } catch (e) {
      reject(Object.assign(new Error('Invalid JSON body'), { status: 400 }))
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
    console.error('Server Error:', error)
    return res.status(500).json({ error: 'Internal Server Error' })
  }
}

module.exports = handler

if (require.main === module) {
  const http = require('http')
  const PORT = process.env.PORT || 3000

  const server = http.createServer(handler)

  if (SOCKET_ENABLED) {
    const wss = new WebSocketServer({ server, path: '/socket', maxPayload: MAX_BODY })

    wss.on('connection', (ws, req) => {
      ws.subscriptions = []
      const ip = clientIp(req)
      const reply = (data) => { if (ws.readyState === 1) ws.send(JSON.stringify(data)) }

      ws.on('message', async (message) => {
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
          console.error('Socket Error:', e)
          reply({ op: type, status: 500, error: 'Internal Server Error' })
        }
      })

      ws.on('close', () => clearSubs(ws))
      ws.on('error', () => clearSubs(ws))
    })
  }

  server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT} (WebSocket ${SOCKET_ENABLED ? 'on' : 'off'})`)
  })
}