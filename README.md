# PulseCheck — API Monitoring System

A system that watches your APIs and tells you when they go down or come back up. Built with 3 separate backend services that talk to each other through Redis.

---

## What's in this project (the simple version)

### Why 3 separate backends instead of 1?

This is called **microservice architecture**. Instead of one giant `server.js` that does everything, we split the work into 3 small servers that each do one job:

| Service          | Port | What it does                                                     |
| ---------------- | ---- | ---------------------------------------------------------------- |
| **Auth**         | 3001 | Sign up, log in, give out JWT tokens                             |
| **Monitoring**   | 3002 | CRUD for monitors + the background loop that actually pings URLs |
| **Notification** | 3003 | Listens for "API went down!" messages and sends emails           |

Each one is its own mini Fastify app with its own `server.js`, routes, controllers, and models. They all share the same MongoDB database but they run independently — if the notification service crashes, the monitoring and auth services keep working fine.

---

## Folder structure explained

```
PulseCheck/
│
├── packages/shared/          👈 Code that ALL services need
│   └── src/
│       ├── config.js         Reads .env file, exports config object
│       ├── db.js             Connects to MongoDB (with retry if it fails)
│       ├── redis.js          Helpers to publish/subscribe to Redis channels
│       ├── auth.js           JWT middleware — verifies the token from headers
│       └── errors.js         Catches errors and returns clean JSON responses
│
├── services/
│   ├── auth/                 👈 Auth Service
│   │   └── src/
│   │       ├── server.js             Starts Fastify on port 3001
│   │       ├── models/User.js        Mongoose schema for users
│   │       ├── routes/auth.routes.js POST /register, POST /login, GET /me
│   │       └── controllers/auth.controller.js  The actual logic
│   │
│   ├── monitoring/           👈 Monitoring Service
│   │   └── src/
│   │       ├── server.js             Starts Fastify on port 3002
│   │       ├── models/
│   │       │   ├── Monitor.js        What URLs to watch
│   │       │   ├── CheckResult.js    Each ping result (UP/DOWN, latency, etc)
│   │       │   └── AlertEvent.js     When status flipped (DOWN→UP or UP→DOWN)
│   │       ├── routes/monitor.routes.js   CRUD + check history
│   │       ├── controllers/monitor.controller.js
│   │       └── scheduler/checker.js  ⭐ THE CORE — loops through monitors and pings them
│   │
│   └── notification/         👈 Notification Service
│       └── src/
│           ├── server.js             Starts Fastify on port 3003
│           ├── models/NotificationLog.js  Record of every email sent
│           ├── routes/notification.routes.js  GET /notifications
│           ├── controllers/notification.controller.js
│           └── subscribers/alertSubscriber.js  ⭐ Listens to Redis, sends emails
│
├── k8s/                      👈 Kubernetes config files (YAML)
├── docker-compose.yml        👈 Run everything in Docker with one command
└── .env                      👈 All your secrets and config
```

---

## What is Redis and why do we use it?

**Redis** = a super fast in-memory database. We use it as a **message bus** between services.

**The problem**: When the monitoring service detects that an API went from UP to DOWN, how does the notification service find out? They're separate servers.

**The solution**: Redis Pub/Sub (publish/subscribe).

```
Monitoring Service                    Notification Service
      |                                      |
      |--- publishes message to ------→ Redis channel "alert:status-change"
      |    Redis channel                     |
      |                              ←------ | subscribes and receives message
      |                                      |
      |                                      |--- sends email to user
```

Think of it like a group chat channel:

- Monitoring **posts** a message: "Hey, Google API is DOWN!"
- Notification is **listening** on that channel, sees the message, and sends an email

The code for this is in:

- `packages/shared/src/redis.js` — the `publish()` and `subscribe()` helpers
- `services/monitoring/src/scheduler/checker.js` — line where it calls `publish()`
- `services/notification/src/subscribers/alertSubscriber.js` — the subscriber that sends emails

---

## What is Docker and why do we use it?

**Docker** = packages your app + all its dependencies into a "container" that runs the same everywhere.

**The problem**: "It works on my machine" — your app needs Node.js v20, MongoDB, Redis, specific npm packages. Setting all this up on another computer is painful.

**The solution**: Docker containers. Each container is like a tiny virtual computer with everything pre-installed.

### Files you should know:

**`Dockerfile`** (one per service) — Recipe for building a container. It says:

1. Start with Node.js 20
2. Copy my code in
3. Run `npm install`
4. Run `node src/server.js`

**`docker-compose.yml`** — Runs ALL containers at once. One command starts:

- Auth service container
- Monitoring service container
- Notification service container
- MongoDB container
- Redis container

```bash
# Start everything
npm run docker:up

# Stop everything
npm run docker:down
```

You don't need MongoDB or Redis installed on your computer — Docker runs them for you.

---

## What is Kubernetes and why do we use it?

**Kubernetes (K8s)** = manages your Docker containers in production. Think of Docker as "how to package" and Kubernetes as "how to run at scale."

**The problem**: In production, you need:

- Multiple copies of each service (if one crashes, others handle traffic)
- Automatic restarts if something dies
- A single URL that routes to the right service
- Easy updates without downtime

**The solution**: Kubernetes handles all of this.

### Files in `k8s/`:

| File                           | What it does                                                                                        |
| ------------------------------ | --------------------------------------------------------------------------------------------------- |
| `auth-deployment.yaml`         | "Run 2 copies of the auth service"                                                                  |
| `auth-service.yaml`            | "Give auth a stable internal address"                                                               |
| `monitoring-deployment.yaml`   | "Run 2 copies of the monitoring service"                                                            |
| `monitoring-service.yaml`      | "Give monitoring a stable internal address"                                                         |
| `notification-deployment.yaml` | "Run 2 copies of the notification service"                                                          |
| `notification-service.yaml`    | "Give notification a stable internal address"                                                       |
| `ingress.yaml`                 | "Route `/api/auth/*` → auth, `/api/monitors/*` → monitoring, `/api/notifications/*` → notification" |

You don't need to learn K8s right now. The files are there for deployment later.

---

## How to run locally (the easy way)

### Option A: Docker Compose (recommended — no setup needed)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Run:

```bash
npm run docker:up
```

3. That's it. Everything starts automatically.

### Option B: Without Docker (need MongoDB + Redis installed)

1. Install and start [MongoDB](https://www.mongodb.com/try/download/community) on port 27017
2. Install and start [Redis](https://redis.io/download) on port 6379
3. Open 3 terminals:

```bash
# Terminal 1
npm run dev:auth

# Terminal 2
npm run dev:monitoring

# Terminal 3
npm run dev:notification
```

---

## Swagger API Docs

Once services are running, open these in your browser to see and test all endpoints:

- Auth: [http://localhost:3001/docs](http://localhost:3001/docs)
- Monitoring: [http://localhost:3002/docs](http://localhost:3002/docs)
- Notification: [http://localhost:3003/docs](http://localhost:3003/docs)

---

## How the code flows (step by step)

### 1. User registers

```
POST http://localhost:3001/api/auth/register
Body: { "email": "you@email.com", "password": "Test1234" }
```

→ `auth.routes.js` → `auth.controller.js` → hashes password → saves to MongoDB → returns JWT token

### 2. User creates a monitor

```
POST http://localhost:3002/api/monitors
Headers: { Authorization: "Bearer <your-jwt-token>" }
Body: { "name": "Google", "url": "https://google.com", "method": "GET", "intervalSeconds": 30 }
```

→ JWT middleware checks token → `monitor.routes.js` → `monitor.controller.js` → saves to MongoDB

### 3. Scheduler pings the URL

`checker.js` runs a `setInterval` loop. Every 30 seconds (or whatever you set):

1. Makes an HTTP request to `https://google.com`
2. Records the result (UP/DOWN, status code, latency) in `CheckResult`
3. If status CHANGED (was UP, now DOWN): creates an `AlertEvent` and publishes to Redis

### 4. Notification service sends email

`alertSubscriber.js` is subscribed to the Redis channel. When it gets a message:

1. Looks up the user's email from MongoDB
2. Sends a styled HTML email via Nodemailer
3. Logs the result (SENT/FAILED) in `NotificationLog`

---

## Environment variables (.env)

| Variable            | What it is                                                        | Default                                |
| ------------------- | ----------------------------------------------------------------- | -------------------------------------- |
| `MONGO_URI`         | MongoDB connection string                                         | `mongodb://localhost:27017/pulsecheck` |
| `REDIS_URL`         | Redis connection string                                           | `redis://localhost:6379`               |
| `JWT_SECRET`        | Secret key for signing JWT tokens — **change this in production** | `dev-secret-change-me`                 |
| `AUTH_PORT`         | Port for auth service                                             | `3001`                                 |
| `MONITORING_PORT`   | Port for monitoring service                                       | `3002`                                 |
| `NOTIFICATION_PORT` | Port for notification service                                     | `3003`                                 |
| `SMTP_HOST`         | Email server host                                                 | `smtp.ethereal.email`                  |
| `SMTP_PORT`         | Email server port                                                 | `587`                                  |
| `SMTP_USER`         | Email username                                                    | (empty = uses fake email for testing)  |
| `SMTP_PASS`         | Email password                                                    | (empty)                                |
| `SMTP_FROM`         | "From" address on emails                                          | `noreply@pulsecheck.dev`               |
