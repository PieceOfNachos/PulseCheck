# 🛰️ PulseTrack — Full-Stack Distributed API Monitoring System

**PulseTrack** is a high-availability monitoring platform designed to track the health, latency, and uptime of external API endpoints. Built with a microservices architecture, it leverages **Redis Pub/Sub** for decoupled communication and **Kubernetes** for resilient orchestration.



---

## 🚀 System Performance & Constraints

The system is engineered to meet strict Non-Functional Requirements (NFRs) validated via **k6** benchmarking:

* **Target Latency:** $\text{Avg Latency} < 120\text{ms}$ under peak load.
* **Concurrency:** Support for $N \ge 500$ concurrent monitored endpoints.
* **Drift Prevention:** Monitoring intervals are synchronized to prevent time-drift ($\Delta t \to 0$).
* **Scalability:** Horizontal scaling of worker nodes via **Kubernetes HPA**.

---

## 🏗️ Architecture & Data Flow

The system is decomposed into three independently deployable services:

1.  **Auth Service:** User registration and JWT-based security.
2.  **Monitoring Service:** The core engine performing periodic pings and health checks.
3.  **Notification Service:** An event-driven worker that dispatches alerts via Email.

### Event-Driven Communication
Services communicate asynchronously via **Redis Pub/Sub**. When a monitor detects a state change:
$$\text{Status Change} \implies \text{Publish}(\text{channel: "alerts"}, \text{payload: AlertEvent})$$

---

## 📊 Domain Models (Deep Dive)

The system utilizes **MongoDB** for persistence with the following core entities:

### 1. Monitor Entity
$$M = \{ id, userId, url, method, intervalSeconds, \text{expectedStatus} \}$$
*Defines the configuration for a specific endpoint check.*

### 2. Check Result
$$C = \{ monitorId, status \in \{UP, DOWN\}, \text{latencyMs}, \text{timestamp} \}$$
*Stored as time-series data to generate historical charts and statistics.*

### 3. Alert Event
$$A = \{ monitorId, type \in \{DOWN, RECOVERED\}, \text{triggeredAt} \}$$

---

## 🛠️ Tech Stack

* **Runtime:** Node.js (Fastify/Express)
* **Database:** MongoDB (Native batching for high-frequency writes)
* **Messaging:** Redis (Pub/Sub + Scheduler + Cache)
* **DevOps:** Docker, Kubernetes (3 Deployments, 3 Services, Ingress Routing)
* **Testing:** k6 (Load Testing), Jest

---

## 📦 Deployment Instructions

### Local Development (Docker Compose)
```bash
docker-compose up --build