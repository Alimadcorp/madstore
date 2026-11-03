# MadStore Documentation

MadStore is a general purpose key-value storage on top of Redis. It supports all operations in both GET, POST, and by Websocket!

## Deployed at https://kv.alimad.co

## Running locally

You need a Redis server (e.g. `docker run -p 6379:6379 redis`).

```
npm install
cp .env.example .env
npm start
```

Open `http://localhost:3000` for the demo control panel.

## Deploying on Railway

1. Add a Redis service to the project and deploy this repo as another service.
2. In this service's variables, set `REDIS_URL` to `${{Redis.REDIS_URL}}` (reference your Redis service; use the private network URL, not the public one, when possible).
3. Optionally set the health check path to `/health`.

`TRUST_PROXY` defaults to `1` on Railway so rate limiting uses the client IP from `X-Forwarded-For`.

## .env

| Variable | Required | Description |
| --- | --- | --- |
| `REDIS_URL` | yes | Redis connection URL. Falls back to `REDIS_PUBLIC_URL`. |
| `REDIS_PREFIX` | no | Prefix for all Redis keys. Default `madstore:`. |
| `SOCKET_MODE` | no | `1` enables WebSocket (default), `0` disables it. |
| `CORS_ORIGIN` | no | Value of `Access-Control-Allow-Origin`. Default `*`. |
| `TRUST_PROXY` | no | `1` to read the client IP from `X-Forwarded-For` for rate limiting. Defaults to `1` on Railway, `0` elsewhere. |
| `PORT` | no | Server port. Defaults to `3000` (Railway sets it for you). |

## Redis data model

Per MadStore key `K` (with the default prefix):

- `madstore:meta:K`: JSON with hashed passwords, max depth, creation time and last accepted `ts`.
- `madstore:data:K`: the key's whole JSON document. Paths are resolved inside this document.
- `madstore:lock:K`: short-lived lock used to make read-modify-write operations atomic.
- `madstore:chg:K`: pub/sub channel used to push changes to WebSocket subscribers (works across multiple instances).

A key's document is limited to 8 MB. Deleting the last child of an object also removes the now-empty parents, and setting an empty object/array deletes that path.

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
| Upsert (merge) | `POST /upsert`, `PUT`, `PATCH` | `key`, `path?`, `value` (flat JSON object, no `/` in keys; a `null` member removes that member), `write?` / `master?` |
| Delete path | `POST /delete` or `DELETE` | `key`, `path`, `write?` / `master?` |
| Delete key | `POST /delete` with `path` `/` | `key`, `master` |
| Change passwords | `POST /password` | `key`, `master`, `new_master?`, `new_read?`, `new_write?` |
| Config | `GET /config` | returns `{ "socket": true \| false }` |
| Health | `GET /health` | `{ "ok": true }` when Redis responds |

Notes:

- `GET` is allowed only for `get`. `create` requires `POST`.
- Method overrides: `DELETE` always means delete, `PUT` and `PATCH` always mean upsert.
- `new_read` / `new_write` set to an empty string make that access public. Omit them to leave unchanged.
- A string `value` is parsed as JSON when possible, otherwise stored as a string.
- Objects containing a `__proto__` member, or nested deeper than 100 levels, are rejected.

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
| 413 | Body or stored data too large |
| 429 | Rate limited |
| 500 | Internal error |
| 503 | Key busy (lock timeout) or Redis unavailable |

## WebSocket API

Endpoint: `/socket` (only when `SOCKET_MODE=1`).

Client messages are JSON: `{ "type": "<op>", "ts": 1700000000000, "body": { ... } }`, where `type` is any HTTP operation name (`get`, `set`, `upsert`, `delete`, `create`, `password`) or `subscribe`. Max message size is 1 MB. Messages on one connection are processed in order.

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
- Each subscription pushes `{ "type": "update", "key", "path", "data", "ts" }` immediately and whenever the data at that path changes (including changes made through other server instances or HTTP).
- Passwords are checked when subscribing, not on later updates.
- Subscriptions are removed when the socket closes. The server pings clients every 30 seconds and drops dead connections.
