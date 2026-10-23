"""Consume RingShield transactions and publish fraud alerts."""

import argparse
import json
import logging
import sys
import time
from typing import Any

from confluent_kafka import Consumer, KafkaError, Message, Producer, TopicPartition

from detection.engine import FraudDetectionEngine
from streaming.config import KafkaConfig

logger = logging.getLogger("ringshield.consumer")


class PoisonPolicy:
    """Poison message policies for malformed messages.

    - SKIP_AND_COMMIT: Log detailed warning (partition, offset, error), skip,
      and commit the offset so the consumer does not get stuck in an infinite loop.
    - SKIP_WITHOUT_COMMIT: Skip message without committing offset.
    - RAISE: Raise an exception to halt the consumer process immediately.
    """

    SKIP_AND_COMMIT = "skip_and_commit"
    SKIP_WITHOUT_COMMIT = "skip_without_commit"
    RAISE = "raise"


class TransactionConsumer:
    """Process input transactions and publish suspicious ones as alerts.

    Delivery Guarantees & Limitations:
    - At-Least-Once Delivery: Alerts are published and confirmed BEFORE committing the input offset.
      If the process crashes after alert delivery but before offset commit, the message will be
      re-read on restart, potentially producing a duplicate alert. Downstream consumers should
      deduplicate alerts using transaction_id. Exactly-once processing is not claimed.
    - Sender Ordering: Messages partitioned by sender_id arrive in chronological order per sender,
      allowing accurate sliding-window state tracking for rapid repeated transfers.
    """

    def __init__(
        self,
        config: KafkaConfig | None = None,
        group_id: str | None = None,
        auto_offset_reset: str = "earliest",
        consumer: Any | None = None,
        alert_producer: Any | None = None,
        detector: FraudDetectionEngine | None = None,
        poison_policy: str = PoisonPolicy.SKIP_AND_COMMIT,
    ) -> None:
        self.config = config or (
            KafkaConfig.from_env() if (consumer is None or alert_producer is None) else None
        )
        self.detector = detector or FraudDetectionEngine()
        self.poison_policy = poison_policy

        if consumer is not None:
            self.consumer = consumer
        else:
            assert self.config is not None
            effective_group = group_id or self.config.group_id
            consumer_config = self.config.client_config({
                "group.id": effective_group,
                "auto.offset.reset": auto_offset_reset,
                "enable.auto.commit": False,
            })
            self.consumer = Consumer(consumer_config)

        if alert_producer is not None:
            self.alert_producer = alert_producer
        else:
            assert self.config is not None
            alert_producer_conf = self.config.client_config({
                "acks": "all",
                "retries": 3,
                "delivery.timeout.ms": 15000,
            })
            self.alert_producer = Producer(alert_producer_conf)

    def publish_alert(
        self, alert: dict[str, Any], timeout: float = 10.0
    ) -> dict[str, Any]:
        """Publish a fraud alert to Kafka with delivery callback confirmation."""
        delivery_info: dict[str, Any] = {}
        delivery_error: list[KafkaError] = []

        def on_alert_delivery(err: KafkaError | None, msg: Any) -> None:
            if err is not None:
                delivery_error.append(err)
                logger.error(
                    "Fraud alert delivery failed for transaction %s: %s",
                    alert.get("transaction_id"),
                    err.str(),
                )
            else:
                delivery_info["topic"] = msg.topic()
                delivery_info["partition"] = msg.partition()
                delivery_info["offset"] = msg.offset()

        topic = self.config.alert_topic if self.config else "fraud-alerts"
        self.alert_producer.produce(
            topic=topic,
            key=alert["transaction_id"].encode("utf-8"),
            value=json.dumps(alert).encode("utf-8"),
            on_delivery=on_alert_delivery,
        )

        remaining = self.alert_producer.flush(timeout=timeout)

        if delivery_error:
            raise RuntimeError(
                f"Fraud alert delivery error for {alert.get('transaction_id')}: "
                f"{delivery_error[0].str()} (code: {delivery_error[0].code()})"
            )

        if not delivery_info:
            raise TimeoutError(
                f"Fraud alert delivery timed out ({remaining} pending) for "
                f"{alert.get('transaction_id')}"
            )

        return delivery_info

    def process_message(self, message: Message) -> dict[str, Any] | None:
        """Process a single Kafka message safely.

        Follows strict ordering:
        1. Decode JSON payload
        2. Evaluate rules with FraudDetectionEngine (runs schema validation)
        3. If suspicious: publish alert to alert_topic and confirm delivery
        4. Commit input offset only after successful processing and alert delivery
        """
        raw_val = message.value()
        try:
            if raw_val is None:
                raise ValueError("Message value is None (tombstone record)")

            transaction = json.loads(raw_val.decode("utf-8"))
            alert = self.detector.evaluate(transaction)

            # If suspicious, publish alert and confirm delivery BEFORE committing offset
            if alert["is_suspicious"]:
                self.publish_alert(alert)
                print(
                    "FRAUD ALERT:",
                    alert["transaction_id"],
                    alert["risk_reasons"],
                    f"Amount: ₹{alert['amount']:,.2f}",
                    flush=True,
                )

            # Commit offset synchronously to guarantee at-least-once processing
            self.consumer.commit(message=message, asynchronous=False)
            return alert if alert["is_suspicious"] else None

        except (ValueError, UnicodeDecodeError, TypeError, json.JSONDecodeError) as exc:
            logger.warning(
                "Malformed message at partition=%s, offset=%s: %s",
                message.partition(),
                message.offset(),
                exc,
            )
            print(
                f"SKIPPED MALFORMED MESSAGE [partition={message.partition()}, offset={message.offset()}]: {exc}",
                flush=True,
            )

            if self.poison_policy == PoisonPolicy.SKIP_AND_COMMIT:
                # Commit malformed message to advance offset and prevent infinite retry loop
                self.consumer.commit(message=message, asynchronous=False)
            elif self.poison_policy == PoisonPolicy.RAISE:
                raise

            return None

    def start(
        self,
        max_messages: int | None = None,
        timeout_seconds: float | None = None,
    ) -> int:
        """Start listening for incoming transactions.

        Parameters:
            max_messages: Stop after processing this many valid/invalid messages.
            timeout_seconds: Stop after this many seconds elapsed.

        Returns:
            Total count of messages processed.
        """
        def on_assign(consumer: Consumer, partitions: list[TopicPartition]) -> None:
            print(
                f"Consumer group assigned {len(partitions)} partition(s): "
                f"{[p.partition for p in partitions]}",
                flush=True,
            )

        topic = self.config.input_topic if self.config else "upi-transactions"
        self.consumer.subscribe([topic], on_assign=on_assign)
        print(f"Listening on topic: {topic}", flush=True)

        processed_count = 0
        start_time = time.time()

        try:
            while True:
                # Check duration timeout
                if timeout_seconds is not None:
                    if time.time() - start_time >= timeout_seconds:
                        print(
                            f"Reached timeout of {timeout_seconds}s. Stopping consumer.",
                            flush=True,
                        )
                        break

                message = self.consumer.poll(1.0)

                if message is None:
                    continue

                if message.error():
                    if message.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    raise RuntimeError(f"Kafka consumer error: {message.error()}")

                self.process_message(message)
                processed_count += 1

                if max_messages is not None and processed_count >= max_messages:
                    print(
                        f"Processed target {processed_count} message(s). Stopping consumer.",
                        flush=True,
                    )
                    break

        except KeyboardInterrupt:
            print("Stopping RingShield consumer...", flush=True)
        finally:
            self.consumer.close()
            self.alert_producer.flush(timeout=10)

        return processed_count


def main() -> None:
    """CLI entrypoint for running the RingShield transaction consumer."""
    parser = argparse.ArgumentParser(
        description="RingShield Fraud Detection Streaming Consumer"
    )
    parser.add_argument(
        "-g",
        "--group-id",
        default=None,
        help="Consumer group ID (default from config or ringshield-fraud-detection)",
    )
    parser.add_argument(
        "-n",
        "--max-messages",
        type=int,
        default=None,
        help="Maximum messages to consume before stopping",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=None,
        help="Timeout in seconds before stopping",
    )
    parser.add_argument(
        "--poison-policy",
        choices=[
            PoisonPolicy.SKIP_AND_COMMIT,
            PoisonPolicy.SKIP_WITHOUT_COMMIT,
            PoisonPolicy.RAISE,
        ],
        default=PoisonPolicy.SKIP_AND_COMMIT,
        help="Handling policy for malformed messages (default: skip_and_commit)",
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

    try:
        config = KafkaConfig.from_env()
    except Exception as exc:
        sys.stderr.write(f"Configuration Error: {exc}\n")
        sys.exit(1)

    consumer = TransactionConsumer(
        config=config,
        group_id=args.group_id,
        poison_policy=args.poison_policy,
    )

    try:
        consumer.start(
            max_messages=args.max_messages,
            timeout_seconds=args.timeout,
        )
    except Exception as exc:
        sys.stderr.write(f"Consumer execution error: {exc}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()