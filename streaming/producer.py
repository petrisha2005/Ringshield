"""Publish RingShield transactions to Kafka."""

import json
import logging
from typing import Any

from confluent_kafka import KafkaError, Producer

from contracts.schemas import validate_transaction
from streaming.config import KafkaConfig

logger = logging.getLogger(__name__)


class TransactionProducer:
    """Send validated transactions to the input Kafka topic with delivery confirmation."""

    def __init__(
        self,
        config: KafkaConfig | None = None,
        delivery_timeout_ms: int = 15000,
        flush_timeout: float = 15.0,
    ) -> None:
        self.config = config or KafkaConfig.from_env()
        self.flush_timeout = flush_timeout

        client_conf = self.config.client_config()
        client_conf.update({
            "acks": "all",
            "retries": 3,
            "retry.backoff.ms": 200,
            "delivery.timeout.ms": delivery_timeout_ms,
            "request.timeout.ms": min(10000, delivery_timeout_ms),
        })

        self.producer = Producer(client_conf)

    def publish(
        self,
        transaction: dict[str, Any],
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Publish a validated transaction to Kafka.

        Uses a delivery callback to confirm broker receipt, partition, and offset.
        Raises RuntimeError on delivery error, or TimeoutError on flush timeout.
        """
        validate_transaction(transaction)

        payload = json.dumps(transaction).encode("utf-8")
        flush_timeout = timeout if timeout is not None else self.flush_timeout

        delivery_info: dict[str, Any] = {}
        delivery_error: list[KafkaError] = []

        def on_delivery(err: KafkaError | None, msg: Any) -> None:
            if err is not None:
                delivery_error.append(err)
                logger.error(
                    "Kafka delivery failed for transaction %s: %s (code %s)",
                    transaction.get("transaction_id"),
                    err.str(),
                    err.code(),
                )
            else:
                delivery_info["topic"] = msg.topic()
                delivery_info["partition"] = msg.partition()
                delivery_info["offset"] = msg.offset()
                delivery_info["transaction_id"] = transaction["transaction_id"]

        self.producer.produce(
            topic=self.config.input_topic,
            key=transaction["transaction_id"].encode("utf-8"),
            value=payload,
            on_delivery=on_delivery,
        )

        remaining = self.producer.flush(timeout=flush_timeout)

        if delivery_error:
            err = delivery_error[0]
            raise RuntimeError(
                f"Kafka delivery failed for transaction '{transaction['transaction_id']}': "
                f"{err.str()} (KafkaError code {err.code()})"
            )

        if not delivery_info:
            raise TimeoutError(
                f"Kafka delivery timed out after {flush_timeout}s: "
                f"{remaining} message(s) still pending delivery in queue. "
                f"Transaction ID: {transaction['transaction_id']}"
            )

        return delivery_info

    def flush(self, timeout: float = 10.0) -> int:
        """Flush any pending messages."""
        return self.producer.flush(timeout=timeout)