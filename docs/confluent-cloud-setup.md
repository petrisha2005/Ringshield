# RingShield: Confluent Cloud Kafka Streaming Setup & Operation

This guide documents how to configure, operate, and troubleshoot the real-time Confluent Cloud Kafka streaming pipeline for RingShield.

---

## 1. Confluent Cloud Cluster Setup

1. Log in to your [Confluent Cloud Console](https://confluent.cloud/).
2. Create an Environment (or select an existing one, e.g. `default`).
3. Create a Cluster:
   - **Type**: Basic or Standard (ideal for hackathon/prototyping).
   - **Cloud Provider & Region**: Choose your preferred cloud (e.g. AWS, GCP, or Azure) and nearest region.
   - Note the **Bootstrap server** address from **Cluster Settings** (e.g. `pkc-xxxxx.region.provider.confluent.cloud:9092`).

---

## 2. Topic Creation

Create two topics in your cluster via the Confluent Cloud web UI or CLI:

| Topic Name | Recommended Partitions | Cleanup Policy | Purpose |
| :--- | :---: | :---: | :--- |
| `upi-transactions` | 6 | `delete` | Incoming transaction event stream. Partitioned by `sender_id`. |
| `fraud-alerts` | 1 | `delete` | Output stream for suspicious fraud alerts. Partitioned by `transaction_id`. |

> **Partition Ordering Note**: In `upi-transactions`, messages use `sender_id` as the message key. Kafka's default Murmur2 hash partitioner routes all transactions from the same sender to the same partition, guaranteeing chronological in-order delivery to the consumer processing that partition.

---

## 3. Generating Cluster API Credentials

1. Inside your Confluent Cloud cluster dashboard, navigate to **API Keys** under **Cluster Overview**.
2. Click **Create Key** -> Choose **Granular access** or **Global access** (for hackathon/demo, Global access provides full Read/Write permissions to topics).
3. Save the generated **API Key** (username) and **API Secret** (password) securely.

---

## 4. Local Environment Configuration

RingShield loads configuration using `python-dotenv`. Create a `.env` file in the project root:

```bash
touch .env
```

Add your Confluent Cloud cluster details to `.env` (never commit this file):

```ini
# Confluent Cloud Kafka Configuration
KAFKA_BOOTSTRAP_SERVERS=pkc-xxxxx.region.cloud.confluent.cloud:9092
KAFKA_API_KEY=your_confluent_api_key
KAFKA_API_SECRET=your_confluent_api_secret

# Topics (defaults used if omitted)
KAFKA_INPUT_TOPIC=upi-transactions
KAFKA_ALERT_TOPIC=fraud-alerts

# Consumer Group ID (default used if omitted)
KAFKA_GROUP_ID=ringshield-fraud-detection
```

> **Security Reminder**: `.env` is listed in `.gitignore`. Never commit or paste `.env` contents into chat or public repositories.

---

## 5. Verifying Cluster Connectivity and Topics

Verify your cluster connectivity and confirm that both topics are reachable using Python:

```bash
PYTHONPATH=. python3 -c "
from confluent_kafka import Producer
from streaming.config import KafkaConfig

cfg = KafkaConfig.from_env()
p = Producer(cfg.client_config())
md = p.list_topics(timeout=10)
print('Connected to cluster:', cfg.masked_summary()['bootstrap_server'])
print('Topics found:', [t for t in md.topics.keys() if not t.startswith('_')])
"
```

Expected output:
```
Connected to cluster: pkc-xxxxx.region.cloud.confluent.cloud
Topics found: ['fraud-alerts', 'upi-transactions']
```

---

## 6. Starting the Streaming Consumer

Open **Terminal Session 1** and start the fraud detection consumer:

```bash
PYTHONUNBUFFERED=1 PYTHONPATH=. python3 -m streaming.consumer
```

### Supported Consumer Flags:
- `-g, --group-id`: Override consumer group ID.
- `-n, --max-messages`: Stop automatically after processing $N$ messages (ideal for automated tests).
- `-t, --timeout`: Stop automatically after $T$ seconds.
- `--poison-policy`: Choose policy for malformed records (`skip_and_commit`, `skip_without_commit`, `raise`). Default is `skip_and_commit`.
- `-v, --verbose`: Enable debug logging.

---

## 7. Publishing Synthetic Transactions

Open **Terminal Session 2** to publish transactions to `upi-transactions`.

### A. Publish the Synthetic Dataset from File:
```bash
PYTHONPATH=. python3 -m streaming.producer -f data/transactions.jsonl
```

### B. Publish with Delay Between Messages (Simulating Real-Time Stream):
```bash
PYTHONPATH=. python3 -m streaming.producer -f data/transactions.jsonl -d 0.5
```

### C. Publish a Single Transaction:
```bash
PYTHONPATH=. python3 -m streaming.producer -s '{
  "transaction_id": "manual_tx_99",
  "sender_id": "vip_user@okhdfcbank",
  "receiver_id": "merchant@icici",
  "amount": 250000.0,
  "timestamp": "2026-10-23T12:00:00Z"
}'
```

### D. Validate Without Publishing (`--dry-run`):
```bash
PYTHONPATH=. python3 -m streaming.producer -f data/transactions.jsonl --dry-run
```

---

## 8. Verifying Fraud Alerts Output

Read alerts published to the `fraud-alerts` topic from the beginning:

```bash
PYTHONPATH=. python3 -c "
import json
from confluent_kafka import Consumer, TopicPartition
from streaming.config import KafkaConfig

cfg = KafkaConfig.from_env()
conf = cfg.client_config({'group.id': 'alert-reader-cli', 'auto.offset.reset': 'earliest'})
c = Consumer(conf)
tp = TopicPartition(cfg.alert_topic, 0, 0)
c.assign([tp])

print('Reading from topic:', cfg.alert_topic)
while True:
    msg = c.poll(1.0)
    if msg is None:
        break
    if not msg.error():
        alert = json.loads(msg.value().decode())
        print(f\"[ALERT] Offset {msg.offset()}: TX={alert['transaction_id']} | Reasons={alert['risk_reasons']} | Amount=₹{alert['amount']:,.2f}\")
c.close()
"
```

---

## 9. Delivery Semantics & Guarantees

### At-Least-Once Delivery
- **Order of Operations**: The consumer evaluates the transaction, and if suspicious, produces the alert to `fraud-alerts` with a **confirmed delivery callback** BEFORE calling `consumer.commit()`.
- **Duplicate Alerts**: If a failure or network disconnection occurs after alert delivery but before offset commit, the message may be re-read upon restart, producing a duplicate alert. Downstream alert handlers should deduplicate using `transaction_id`. Exactly-once processing is not claimed.
- **Failed Alert Delivery**: If alert delivery times out or fails, the consumer does **not** commit the input message offset, ensuring no alerts are lost.

### Poison-Pill Message Policy
- If a message contains invalid JSON or violates the required UPI transaction schema, `TransactionConsumer` logs the record with partition, offset, and error details.
- Under the default `skip_and_commit` policy, the offset is committed so that a single corrupted record does not block consumer group progress indefinitely.

---

## 10. Stopping Processes Safely

- Press `Ctrl+C` in the consumer or producer terminal.
- Both clients intercept `KeyboardInterrupt` and gracefully execute:
  1. `alert_producer.flush(timeout=10)` — delivers any buffered alerts.
  2. `consumer.close()` — commits offsets and triggers clean consumer group leave (`LeaveGroupRequest`).

---

## 11. Troubleshooting Common Issues

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| `Missing required Kafka configuration` | `.env` file missing or environment variables not exported. | Ensure `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_API_KEY`, and `KAFKA_API_SECRET` are set. |
| `SASL authentication error` | Invalid API key or API secret. | Regenerate API keys in Confluent Cloud and verify copy-paste without trailing whitespace. |
| `Topic authorization failed` | API key lacks read/write ACLs for topic. | Use an API key with cluster-wide or topic-specific Read/Write permissions. |
| `1 Kafka message(s) still pending delivery` | Timeout before broker connection/TLS handshake established. | Ensure `delivery.timeout.ms=15000` and `flush_timeout=15.0`. Confluent Cloud brokers may take a few seconds on initial connection. |
| Consumer does not receive messages | Consumer group offset is committed to the end of topic. | Use a fresh consumer group via `-g my-test-group` or start with `auto_offset_reset='earliest'`. |

---

## 12. Running Offline Replay Independently

To run without Kafka or Confluent Cloud credentials:

```bash
# Run unit test suite (49 tests, 100% offline)
PYTHONPATH=. python3 -m pytest -v

# Run local offline replay benchmark
PYTHONPATH=. python3 -m streaming.replay -i data/transactions.jsonl -o data/alerts.jsonl
```

---

## 13. Verification Matrix

| Step | Environment | Verified Status |
| :--- | :--- | :---: |
| Unit tests (49/49 passing) | Local (Offline Mocks) | **VERIFIED** |
| Offline replay & latency benchmark | Local File I/O | **VERIFIED** |
| Confluent Cloud cluster connection & topic discovery | Confluent Cloud | **VERIFIED** |
| Real-time producer delivery callbacks (partition & offset) | Confluent Cloud | **VERIFIED** |
| Real-time consumer evaluation & alert delivery | Confluent Cloud | **VERIFIED** |
| Poison-pill detection & non-blocking offset commit | Confluent Cloud | **VERIFIED** |
