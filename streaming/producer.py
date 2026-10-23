"""Publish RingShield transactions to Kafka with delivery confirmation and robust error classification."""

import argparse
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any

from confluent_kafka import KafkaError, Producer

from contracts.schemas import validate_transaction
from streaming.config import KafkaConfig

logger = logging.getLogger("ringshield.producer")


class KafkaDeliveryError(RuntimeError, TimeoutError):
    """Raised when Kafka message delivery fails or times out.

    Inherits from both RuntimeError and TimeoutError for backwards compatibility.

    Attributes:
        category: Categorized failure reason (e.g. TIMEOUT, AUTHENTICATION_FAILED,
                  AUTHORIZATION_FAILED, BROKER_UNAVAILABLE, DELIVERY_FAILED, QUEUE_FULL).
        transaction_id: The ID of the transaction that failed.
        kafka_error: The underlying Confluent KafkaError (if available).
    """

    def __init__(
        self,
        message: str,
        category: str = "DELIVERY_FAILED",
        transaction_id: str | None = None,
        kafka_error: KafkaError | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.transaction_id = transaction_id
        self.kafka_error = kafka_error


def sanitize_error_message(msg: str, secrets: list[str] | None = None) -> str:
    """Sanitize error messages to ensure no credentials or secrets are leaked."""
    if not msg:
        return ""
    sanitized = str(msg)
    if secrets:
        for s in secrets:
            if s and len(s) >= 3:
                sanitized = sanitized.replace(s, "[REDACTED]")
    return sanitized


def classify_kafka_error(err: Any) -> str:
    """Classify a KafkaError into a clear diagnostic failure category."""
    if err is None:
        return "UNKNOWN_ERROR"
    code = err.code() if hasattr(err, "code") else None
    if code in (KafkaError._AUTHENTICATION, KafkaError.SASL_AUTHENTICATION_FAILED):
        return "AUTHENTICATION_FAILED"
    if code in (
        KafkaError.TOPIC_AUTHORIZATION_FAILED,
        KafkaError.GROUP_AUTHORIZATION_FAILED,
        KafkaError.CLUSTER_AUTHORIZATION_FAILED,
    ):
        return "AUTHORIZATION_FAILED"
    if code in (
        KafkaError._MSG_TIMED_OUT,
        KafkaError._TIMED_OUT,
        KafkaError.REQUEST_TIMED_OUT,
    ):
        return "TIMEOUT"
    if code in (
        KafkaError._ALL_BROKERS_DOWN,
        KafkaError._TRANSPORT,
        KafkaError._RESOLVE,
    ):
        return "BROKER_UNAVAILABLE"
    if code == KafkaError._QUEUE_FULL:
        return "QUEUE_FULL"
    return "DELIVERY_FAILED"


class TransactionProducer:
    """Send validated transactions to the input Kafka topic with delivery confirmation.

    By default, uses sender_id as the message key.
    Partition Ordering Implication:
        Using sender_id as the Kafka message key ensures that all transactions
        originating from the same sender are routed to the same Kafka partition
        via Kafka's default Murmur2 hash partitioner. This preserves strict
        chronological ordering per sender and guarantees that a consumer thread
        processing that partition evaluates rapid repeated transfers reliably.
    """

    def __init__(
        self,
        config: KafkaConfig | None = None,
        delivery_timeout_ms: int = 15000,
        flush_timeout: float | None = None,
        producer: Any | None = None,
        key_field: str = "sender_id",
    ) -> None:
        self.config = config or (KafkaConfig.from_env() if producer is None else None)
        self.delivery_timeout_ms = delivery_timeout_ms
        if flush_timeout is not None:
            self.flush_timeout = flush_timeout
        else:
            # Ensure flush_timeout provides enough buffer for librdkafka delivery timeout
            self.flush_timeout = max(20.0, (delivery_timeout_ms / 1000.0) + 3.0)
        self.key_field = key_field
        self._last_broker_error: list[KafkaError] = []
        self._secrets: list[str] = []
        if self.config and self.config.api_secret:
            self._secrets.append(self.config.api_secret)

        if producer is not None:
            self.producer = producer
        else:
            assert self.config is not None

            def error_cb(err: KafkaError) -> None:
                self._last_broker_error.append(err)
                safe_err_str = sanitize_error_message(err.str(), self._secrets)
                logger.warning(
                    "Kafka client background error: %s (code %s)",
                    safe_err_str,
                    err.code(),
                )

            client_conf = self.config.client_config({
                "client.id": "ringshield-producer",
                "acks": "all",
                "retries": 3,
                "retry.backoff.ms": 200,
                "delivery.timeout.ms": self.delivery_timeout_ms,
                "request.timeout.ms": min(10000, self.delivery_timeout_ms),
                "error_cb": error_cb,
            })
            self.producer = Producer(client_conf)

    def __enter__(self) -> "TransactionProducer":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def publish(
        self,
        transaction: dict[str, Any],
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Publish a single validated transaction to Kafka synchronously.

        Uses a delivery callback to confirm broker receipt, partition, and offset.
        Raises KafkaDeliveryError on delivery failure or timeout.
        """
        validate_transaction(transaction)

        payload = json.dumps(transaction).encode("utf-8")
        flush_timeout = timeout if timeout is not None else self.flush_timeout

        # Partition key: default to sender_id for per-sender partition ordering
        key_val = str(transaction.get(self.key_field) or transaction["transaction_id"])
        key = key_val.encode("utf-8")

        delivery_info: dict[str, Any] = {}
        delivery_error: list[KafkaError] = []

        def on_delivery(err: KafkaError | None, msg: Any) -> None:
            if err is not None:
                delivery_error.append(err)
                err_str = err.str() if hasattr(err, "str") else str(err)
                err_code = err.code() if hasattr(err, "code") else "UNKNOWN"
                safe_str = sanitize_error_message(err_str, self._secrets)
                logger.error(
                    "Kafka delivery callback error for transaction %s: %s (code %s)",
                    transaction.get("transaction_id"),
                    safe_str,
                    err_code,
                )
            else:
                delivery_info["topic"] = msg.topic()
                delivery_info["partition"] = msg.partition()
                delivery_info["offset"] = msg.offset()
                delivery_info["transaction_id"] = transaction["transaction_id"]

        topic = self.config.input_topic if self.config else "upi-transactions"
        try:
            self.producer.produce(
                topic=topic,
                key=key,
                value=payload,
                on_delivery=on_delivery,
            )
        except BufferError:
            # Local librdkafka queue full, poll once to service callbacks and retry produce
            if hasattr(self.producer, "poll"):
                self.producer.poll(0.5)
            try:
                self.producer.produce(
                    topic=topic,
                    key=key,
                    value=payload,
                    on_delivery=on_delivery,
                )
            except Exception as exc:
                category = "QUEUE_FULL"
                raise KafkaDeliveryError(
                    f"[{category}] Kafka producer queue full for transaction '{transaction['transaction_id']}': {exc}",
                    category=category,
                    transaction_id=transaction["transaction_id"],
                ) from exc
        except Exception as exc:
            category = "PRODUCE_FAILED"
            raise KafkaDeliveryError(
                f"[{category}] Failed to enqueue transaction '{transaction['transaction_id']}': {exc}",
                category=category,
                transaction_id=transaction["transaction_id"],
            ) from exc

        remaining = self.producer.flush(timeout=flush_timeout)

        # 1. Check if delivery callback reported an error
        if delivery_error:
            err = delivery_error[0]
            category = classify_kafka_error(err)
            err_str = err.str() if hasattr(err, "str") else str(err)
            err_code = err.code() if hasattr(err, "code") else "UNKNOWN"
            safe_msg = sanitize_error_message(err_str, self._secrets)
            raise KafkaDeliveryError(
                f"[{category}] Kafka delivery failed for transaction '{transaction['transaction_id']}': "
                f"{safe_msg} (KafkaError code {err_code})",
                category=category,
                transaction_id=transaction["transaction_id"],
                kafka_error=err,
            )

        # 2. Check if flush timed out with message unconfirmed
        if not delivery_info:
            # Check if background error_cb captured a broker-level error
            broker_err = self._last_broker_error[-1] if self._last_broker_error else None
            category = classify_kafka_error(broker_err) if broker_err else "TIMEOUT"

            # Clean up pending message in queue to prevent dangling queue leaks on termination
            if hasattr(self.producer, "purge"):
                try:
                    self.producer.purge(in_queue=True, in_flight=True, blocking=True)
                    if hasattr(self.producer, "poll"):
                        self.producer.poll(0.1)
                except Exception:
                    pass

            err_detail = ""
            if broker_err:
                broker_str = broker_err.str() if hasattr(broker_err, "str") else str(broker_err)
                safe_broker = sanitize_error_message(broker_str, self._secrets)
                err_detail = f" (Broker error: {safe_broker})"

            raise KafkaDeliveryError(
                f"[{category}] Kafka delivery timed out after {flush_timeout:.1f}s: "
                f"{remaining} message(s) still pending delivery in queue{err_detail}. "
                f"Transaction ID: '{transaction['transaction_id']}'",
                category=category,
                transaction_id=transaction["transaction_id"],
                kafka_error=broker_err,
            )

        return delivery_info

    def publish_file(
        self,
        file_path: str | Path,
        limit: int | None = None,
        delay_seconds: float = 0.0,
        dry_run: bool = False,
    ) -> dict[str, int]:
        """Publish transactions from a JSONL file.

        Returns a dictionary with 'attempted', 'delivered', 'failed', and 'invalid' counts.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Transaction file not found: {path}")

        stats = {"attempted": 0, "delivered": 0, "failed": 0, "invalid": 0}

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str:
                    continue

                stats["attempted"] += 1
                try:
                    tx = json.loads(line_str)
                    validate_transaction(tx)
                except (json.JSONDecodeError, ValueError) as exc:
                    stats["invalid"] += 1
                    logger.warning("Line %d invalid: %s", line_num, exc)
                    continue

                if dry_run:
                    stats["delivered"] += 1
                    print(
                        f"[DRY-RUN] Validated transaction {tx['transaction_id']} "
                        f"(sender={tx['sender_id']}, amount=₹{tx['amount']:,.2f})"
                    )
                    continue

                try:
                    res = self.publish(tx)
                    stats["delivered"] += 1
                    print(
                        f"Delivered {tx['transaction_id']} -> "
                        f"topic={res['topic']} partition={res['partition']} offset={res['offset']}"
                    )
                except Exception as exc:
                    stats["failed"] += 1
                    logger.error("Failed delivering line %d: %s", line_num, exc)

                if limit is not None and stats["attempted"] >= limit:
                    break

                if delay_seconds > 0:
                    time.sleep(delay_seconds)

        return stats

    def flush(self, timeout: float = 10.0) -> int:
        """Flush any pending messages in the producer queue."""
        return self.producer.flush(timeout=timeout)

    def close(self, timeout: float = 10.0) -> None:
        """Flush and safely close the producer."""
        try:
            remaining = self.flush(timeout=timeout)
            if remaining > 0 and hasattr(self.producer, "purge"):
                self.producer.purge(in_queue=True, in_flight=True, blocking=True)
                if hasattr(self.producer, "poll"):
                    self.producer.poll(0.1)
        except Exception:
            pass


def main() -> None:
    """CLI entrypoint for publishing transactions to Kafka."""
    parser = argparse.ArgumentParser(
        description="RingShield Transaction Publisher for Kafka"
    )
    parser.add_argument(
        "-f",
        "--file",
        default=None,
        help="Path to JSONL file with transactions to publish (e.g. data/transactions.jsonl)",
    )
    parser.add_argument(
        "-s",
        "--single",
        default=None,
        help="Single transaction JSON string to publish",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=None,
        help="Maximum number of transactions to publish from file",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between publishing messages (default: 0.0)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate transactions without publishing to Kafka",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.file and not args.single:
        parser.print_help()
        sys.exit(1)

    try:
        config = None if args.dry_run else KafkaConfig.from_env()
    except Exception as exc:
        sys.stderr.write(f"Configuration Error: {exc}\n")
        sys.exit(1)

    producer = TransactionProducer(config=config)
    exit_code = 0

    try:
        if args.single:
            try:
                tx = json.loads(args.single)
                if args.dry_run:
                    validate_transaction(tx)
                    print(f"[DRY-RUN] Successfully validated: {tx.get('transaction_id')}")
                else:
                    res = producer.publish(tx)
                    print(
                        f"Published transaction {res['transaction_id']} to "
                        f"topic={res['topic']} partition={res['partition']} offset={res['offset']}"
                    )
            except Exception as exc:
                sys.stderr.write(f"Publish error: {exc}\n")
                exit_code = 1

        if args.file and exit_code == 0:
            try:
                stats = producer.publish_file(
                    file_path=args.file,
                    limit=args.limit,
                    delay_seconds=args.delay,
                    dry_run=args.dry_run,
                )
                print(
                    f"\nFinished publishing file '{args.file}': "
                    f"attempted={stats['attempted']}, delivered={stats['delivered']}, "
                    f"failed={stats['failed']}, invalid={stats['invalid']}"
                )
                if stats["failed"] > 0:
                    exit_code = 2
            except Exception as exc:
                sys.stderr.write(f"File publishing error: {exc}\n")
                exit_code = 1
    finally:
        producer.close()

    if exit_code != 0:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()