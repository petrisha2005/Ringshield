"""Consume RingShield transactions and publish fraud alerts."""

import json
import logging
from typing import Any

from confluent_kafka import Consumer, KafkaError, Message, Producer, TopicPartition

from detection.engine import FraudDetectionEngine
from streaming.config import KafkaConfig

logger = logging.getLogger(__name__)


class TransactionConsumer:
    """Process input transactions and publish suspicious ones as alerts."""

    def __init__(
        self,
        config: KafkaConfig | None = None,
        group_id: str = "ringshield-fraud-detection",
        auto_offset_reset: str = "earliest",
    ) -> None:
        self.config = config or KafkaConfig.from_env()
        self.detector = FraudDetectionEngine()

        consumer_config = self.config.client_config()
        consumer_config.update({
            "group.id": group_id,
            "auto.offset.reset": auto_offset_reset,
            "enable.auto.commit": False,
        })

        self.consumer = Consumer(consumer_config)

        alert_producer_conf = self.config.client_config()
        alert_producer_conf.update({
            "acks": "all",
            "retries": 3,
            "delivery.timeout.ms": 15000,
        })
        self.alert_producer = Producer(alert_producer_conf)

    def publish_alert(self, alert: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
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

        self.alert_producer.produce(
            topic=self.config.alert_topic,
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
                f"Fraud alert delivery timed out ({remaining} pending) for {alert.get('transaction_id')}"
            )

        return delivery_info

    def process_message(self, message: Message) -> dict[str, Any] | None:
        """Process a single Kafka message safely.

        Malformed messages are logged and committed to avoid infinite retry loops.
        Returns the alert dict if an alert was generated, else None.
        """
        raw_val = message.value()
        try:
            if raw_val is None:
                raise ValueError("Message value is None (tombstone)")

            transaction = json.loads(raw_val.decode("utf-8"))
            alert = self.detector.evaluate(transaction)

            if alert["is_suspicious"]:
                self.publish_alert(alert)
                print(
                    "FRAUD ALERT:",
                    alert["transaction_id"],
                    alert["risk_reasons"],
                    f"Amount: ₹{alert['amount']:,.2f}",
                )

            self.consumer.commit(message=message, asynchronous=False)
            return alert if alert["is_suspicious"] else None

        except (ValueError, UnicodeDecodeError, TypeError, json.JSONDecodeError) as exc:
            # Poison pill protection: Malformed messages cannot be fixed on retry.
            # Commit the offset so the consumer does not get stuck in an infinite retry loop.
            logger.warning(
                "Skipping and committing malformed message at partition=%s, offset=%s: %s",
                message.partition(),
                message.offset(),
                exc,
            )
            print(
                f"SKIPPED MALFORMED MESSAGE [partition={message.partition()}, offset={message.offset()}]: {exc}"
            )
            self.consumer.commit(message=message, asynchronous=False)
            return None

    def start(self, max_messages: int | None = None) -> None:
        """Start listening for incoming transactions."""
        def on_assign(consumer: Consumer, partitions: list[TopicPartition]) -> None:
            print(
                f"Consumer group assigned {len(partitions)} partition(s): "
                f"{[p.partition for p in partitions]}",
                flush=True,
            )

        self.consumer.subscribe([self.config.input_topic], on_assign=on_assign)
        print(f"Listening on topic: {self.config.input_topic}", flush=True)

        processed_count = 0
        try:
            while True:
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
                    print(f"Processed {processed_count} message(s). Stopping consumer.", flush=True)
                    break

        except KeyboardInterrupt:
            print("Stopping RingShield consumer...", flush=True)
        finally:
            self.consumer.close()
            self.alert_producer.flush(timeout=10)