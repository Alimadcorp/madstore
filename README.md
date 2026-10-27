# MadStore Documentation

MadStore is a general purpose key-value storage on top of Firebase RTDB. It supports all operations in both GET, POST, and by Websocket!

## Deployed at https://kv.alimad.co

## Running locally

```
npm install
cp .env.example .env
npm start
```

Open `http://localhost:3000` for the demo control panel.

## .env

| Variable | Required | Description |
| --- | --- | --- |
| `FIREBASE_DATABASE_URL` | yes | Realtime Database URL. |
| `FIREBASE_SERVICE_ACCOUNT` | one of | Service account JSON, raw or base64-encoded. Preferred on Vercel. |
| `GOOGLE_APPLICATION_CREDENTIALS` | one of | Path to a service account file. Falls back to `rtdb.json` next to `index.js`. |
| `SOCKET_MODE` | no | `1` enables WebSocket, `0` disables it. Defaults to `1` locally and `0` on Vercel. |
| `CORS_ORIGIN` | no | Value of `Access-Control-Allow-Origin`. Default `*`. |
| `TRUST_PROXY` | no | `1` to read the client IP from `X-Forwarded-For` for rate limiting. Defaults to `1` for Vercel. |
| `PORT` | no | Local server port. Defaults to `3000`. |

## Concepts

- **Key**: 1-64 characters, `A-Z a-z 0-9 _ -`.
- **Master password**: allows read, write, and change in all passwords
- **Read / write password**: access to read/write without a password is allowed when a password is left empty for read/write during key creation
- **Max depth**: maximum number of path segments (max 20, default 5).
- **Path**: `/`-separated. Characters `. # $ [ ]` and control characters in segments are replaced by `_`.
- **ts**: optional integer timestamp. Write operations with a `ts` older than the key's last accepted `ts` are rejected with `409`. A `ts` more than 5 minutes in the future is rejected.

## HTTP API

All responses are JSON. Request bodies are JSON objects, max 1 MB.

Secrets (`master`, `read`, `write`) are accepted in the JSON body or in the headers `X-Master`, `X-Read`, `X-Write`. They are **not** accepted from the query string, so they do not end up in URLs and logs. Only `key`, `path`, `ts` and `depth` may be given in the query string.

| Operation | Request | Body fields |
| --- | --- | --- |
| Create key | `POST /create` | `key`, `master`, `read?`, `write?`, `depth?`, `ts?` |
| Get | `GET /get?key=K&path=/a/b` or `POST /get` | `key`, `path?`, `read?` / `master?` |
| Set (overwrite) | `POST /set` | `key`, `path?`, `value`, `write?` / `master?` |
| Upsert (merge) | `POST /upsert`, `PUT`, `PATCH` | `key`, `path?`, `value` (flat JSON object, no `/` in keys), `write?` / `master?` |
| Delete path | `POST /delete` or `DELETE` | `key`, `path`, `write?` / `master?` |
| Delete key | `POST /delete` with `path` `/` | `key`, `master` |
| Change passwords | `POST /password` | `key`, `master`, `new_master?`, `new_read?`, `new_write?` |
| Config | `GET /config` | returns `{ "socket": true \| false }` |

Notes:

- `GET` is allowed only for `get`. `create` requires `POST`.
- Method overrides: `DELETE` always means delete, `PUT` and `PATCH` always mean upsert.
- `new_read` / `new_write` set to an empty string make that access public. Omit them to leave unchanged.
- A string `value` is parsed as JSON when possible, otherwise stored as a string.

Example:

```
curl -X POST http://localhost:3000/set \
  -H "Content-Type: application/json" \
  -H "X-Write: my-write-pass" \
  -d '{"key":"demo","path":"/users/1","value":{"name":"Ada"}}'
```

### Status codes

| Code | Meaning |
| --- | --- |
| 200 / 201 | Success / key created |
| 400 | Invalid or missing parameter, invalid data |
| 403 | Wrong password, depth exceeded |
| 404 | Key or route not found |
| 405 | Method not allowed |
| 409 | Key exists, or `ts` older than last accepted |
| 413 | Body too large |
| 429 | Rate limited |
| 500 | Internal error |

## WebSocket API

Endpoint: `/socket` (only when `SOCKET_MODE=1`). Not available on Vercel serverless; run the app on a long-lived host for WebSocket.

Client messages are JSON: `{ "type": "<op>", "ts": 1700000000000, "body": { ... } }`, where `type` is any HTTP operation name (`get`, `set`, `upsert`, `delete`, `create`, `password`) or `subscribe`. Max message size is 1 MB.

Replies to operations: `{ "op": "<type>", "status": 200, ...same JSON as HTTP }`.

### Subscribing

```
{
  "type": "subscribe",
  "body": { "keys": [ { "key": "demo", "path": "/users", "read": "...", "master": "..." } ] }
}
```

- `path` may be any sub-path within the key's max depth; the default is `/`.
- Up to 10 entries per message.
- **Every `subscribe` message first removes all of the connection's previous subscriptions**, then creates the new ones.
- Each subscription pushes `{ "type": "update", "key", "path", "data", "ts" }` immediately and on every change.
- Subscriptions are removed when the socket closes.

## Deploying to Vercel

1. Push the repo (`.env` and `rtdb.json` are git-ignored).
2. Import it in Vercel. `vercel.json` routes every request to `index.js` and bundles `index.html`.
3. Set environment variables: `FIREBASE_DATABASE_URL` and `FIREBASE_SERVICE_ACCOUNT` (paste the service account JSON, or its base64).
4. Deploy. 
