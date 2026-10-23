"""Unit tests for RingShield streaming components using mock Kafka clients.

Zero external network or Confluent Cloud credentials required.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call

import pytest
from confluent_kafka import KafkaError

from detection.engine import FraudDetectionEngine
from streaming.config import KafkaConfig
from streaming.consumer import PoisonPolicy, TransactionConsumer
from streaming.producer import (
    KafkaDeliveryError,
    TransactionProducer,
    classify_kafka_error,
    sanitize_error_message,
)


class MockKafkaMessage:
    """Mock Kafka message for consumer unit tests."""

    def __init__(
        self,
        value: bytes | None,
        key: bytes = b"test_key",
        topic: str = "upi-transactions",
        partition: int = 0,
        offset: int = 42,
        error_val: Any = None,
    ) -> None:
        self._value = value
        self._key = key
        self._topic = topic
        self._partition = partition
        self._offset = offset
        self._error = error_val

    def value(self) -> bytes | None:
        return self._value

    def key(self) -> bytes:
        return self._key

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def error(self) -> Any:
        return self._error


# ---------------------------------------------------------------------------
# KafkaConfig Tests
# ---------------------------------------------------------------------------


def test_kafka_config_from_env_success(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "mock.confluent.cloud:9092")
    monkeypatch.setenv("KAFKA_API_KEY", "MOCK_KEY_1234")
    monkeypatch.setenv("KAFKA_API_SECRET", "MOCK_SECRET_5678")
    monkeypatch.setenv("KAFKA_INPUT_TOPIC", "test-input")
    monkeypatch.setenv("KAFKA_ALERT_TOPIC", "test-alerts")
    monkeypatch.setenv("KAFKA_GROUP_ID", "test-group")

    cfg = KafkaConfig.from_env()
    assert cfg.bootstrap_servers == "mock.confluent.cloud:9092"
    assert cfg.api_key == "MOCK_KEY_1234"
    assert cfg.input_topic == "test-input"
    assert cfg.alert_topic == "test-alerts"
    assert cfg.group_id == "test-group"

    client_conf = cfg.client_config({"extra.option": "test"})
    assert client_conf["bootstrap.servers"] == "mock.confluent.cloud:9092"
    assert client_conf["security.protocol"] == "SASL_SSL"
    assert client_conf["sasl.username"] == "MOCK_KEY_1234"
    assert client_conf["extra.option"] == "test"

    summary = cfg.masked_summary()
    assert summary["api_key"] == "MO****34"
    assert "MOCK_SECRET_5678" not in str(summary)


def test_kafka_config_from_env_missing_raises_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)
    monkeypatch.delenv("KAFKA_API_KEY", raising=False)
    monkeypatch.delenv("KAFKA_API_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="Missing required Kafka configuration"):
        KafkaConfig.from_env()


# ---------------------------------------------------------------------------
# TransactionProducer Tests
# ---------------------------------------------------------------------------


def test_producer_publish_success():
    mock_prod = MagicMock()

    def mock_produce(topic, key, value, on_delivery):
        # Simulate successful broker ack during flush
        mock_msg = MagicMock()
        mock_msg.topic.return_value = topic
        mock_msg.partition.return_value = 2
        mock_msg.offset.return_value = 101
        on_delivery(None, mock_msg)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
        input_topic="upi-transactions",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    tx = {
        "transaction_id": "tx_unit_01",
        "sender_id": "alice@upi",
        "receiver_id": "bob@upi",
        "amount": 500.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    res = producer.publish(tx)

    assert res["topic"] == "upi-transactions"
    assert res["partition"] == 2
    assert res["offset"] == 101
    assert res["transaction_id"] == "tx_unit_01"

    # Verify sender_id was used as key for partition ordering
    mock_prod.produce.assert_called_once()
    call_args = mock_prod.produce.call_args[1]
    assert call_args["key"] == b"alice@upi"
    assert call_args["topic"] == "upi-transactions"


def test_producer_publish_delivery_failure():
    mock_prod = MagicMock()

    def mock_produce(topic, key, value, on_delivery):
        err = MagicMock()
        err.str.return_value = "Broker transport failure"
        err.code.return_value = KafkaError._TRANSPORT
        on_delivery(err, None)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    with pytest.raises(RuntimeError, match="Kafka delivery failed") as exc_info:
        producer.publish({
            "transaction_id": "tx_fail",
            "sender_id": "alice@upi",
            "receiver_id": "bob@upi",
            "amount": 500.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })

    err_obj = exc_info.value
    assert isinstance(err_obj, KafkaDeliveryError)
    assert err_obj.category == "BROKER_UNAVAILABLE"
    assert err_obj.transaction_id == "tx_fail"
    assert err_obj.kafka_error is not None


def test_producer_publish_timeout():
    mock_prod = MagicMock()
    # Simulate flush timeout where 1 message remains in queue
    mock_prod.flush.return_value = 1

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    with pytest.raises(TimeoutError, match="Kafka delivery timed out") as exc_info:
        producer.publish({
            "transaction_id": "tx_to",
            "sender_id": "alice@upi",
            "receiver_id": "bob@upi",
            "amount": 500.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })

    err_obj = exc_info.value
    assert isinstance(err_obj, KafkaDeliveryError)
    assert isinstance(err_obj, RuntimeError)  # Backwards compatibility
    assert err_obj.category == "TIMEOUT"
    assert err_obj.transaction_id == "tx_to"
    assert "1 message(s) still pending delivery in queue" in str(err_obj)
    # Verify purge was called to prevent dangling queue leaks on exit
    mock_prod.purge.assert_called_once_with(in_queue=True, in_flight=True, blocking=True)


def test_producer_safe_error_handling_no_credential_leak():
    mock_prod = MagicMock()
    mock_secret = "SUPER_SECRET_TOKEN_XYZ987"

    def mock_produce(topic, key, value, on_delivery):
        err = MagicMock()
        err.str.return_value = f"SASL handshake failed using credentials: {mock_secret}"
        err.code.return_value = KafkaError.SASL_AUTHENTICATION_FAILED
        on_delivery(err, None)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="test_api_key",
        api_secret=mock_secret,
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    with pytest.raises(KafkaDeliveryError) as exc_info:
        producer.publish({
            "transaction_id": "tx_sec_leak",
            "sender_id": "alice@upi",
            "receiver_id": "bob@upi",
            "amount": 500.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })

    err_msg = str(exc_info.value)
    assert mock_secret not in err_msg
    assert "[REDACTED]" in err_msg
    assert exc_info.value.category == "AUTHENTICATION_FAILED"


def test_classify_kafka_error_categories():
    err_auth = MagicMock()
    err_auth.code.return_value = KafkaError.SASL_AUTHENTICATION_FAILED
    assert classify_kafka_error(err_auth) == "AUTHENTICATION_FAILED"

    err_topic_auth = MagicMock()
    err_topic_auth.code.return_value = KafkaError.TOPIC_AUTHORIZATION_FAILED
    assert classify_kafka_error(err_topic_auth) == "AUTHORIZATION_FAILED"

    err_timeout = MagicMock()
    err_timeout.code.return_value = KafkaError._MSG_TIMED_OUT
    assert classify_kafka_error(err_timeout) == "TIMEOUT"

    err_broker = MagicMock()
    err_broker.code.return_value = KafkaError._ALL_BROKERS_DOWN
    assert classify_kafka_error(err_broker) == "BROKER_UNAVAILABLE"

    err_queue = MagicMock()
    err_queue.code.return_value = KafkaError._QUEUE_FULL
    assert classify_kafka_error(err_queue) == "QUEUE_FULL"

    assert classify_kafka_error(None) == "UNKNOWN_ERROR"


def test_producer_queue_full_recovery():
    mock_prod = MagicMock()
    calls = []

    def mock_produce(topic, key, value, on_delivery):
        if not calls:
            calls.append("failed")
            raise BufferError("Local: Queue full")
        calls.append("succeeded")
        msg = MagicMock()
        msg.topic.return_value = topic
        msg.partition.return_value = 0
        msg.offset.return_value = 77
        on_delivery(None, msg)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    res = producer.publish({
        "transaction_id": "tx_queue_retry",
        "sender_id": "alice@upi",
        "receiver_id": "bob@upi",
        "amount": 500.0,
        "timestamp": "2026-10-23T10:00:00Z",
    })
    assert res["offset"] == 77
    assert calls == ["failed", "succeeded"]
    mock_prod.poll.assert_called_once_with(0.5)


def test_producer_context_manager_and_close():
    mock_prod = MagicMock()
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )

    with TransactionProducer(config=cfg, producer=mock_prod) as producer:
        assert producer is not None

    mock_prod.flush.assert_called()


def test_producer_publish_file(tmp_path: Path):
    mock_prod = MagicMock()

    def mock_produce(topic, key, value, on_delivery):
        msg = MagicMock()
        msg.topic.return_value = topic
        msg.partition.return_value = 0
        msg.offset.return_value = 1
        on_delivery(None, msg)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    # File with 2 valid transactions and 1 invalid JSON
    file_path = tmp_path / "test_txs.jsonl"
    file_path.write_text(
        json.dumps({
            "transaction_id": "f_tx_1",
            "sender_id": "a@upi",
            "receiver_id": "b@upi",
            "amount": 100.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })
        + "\n{ corrupted json \n"
        + json.dumps({
            "transaction_id": "f_tx_2",
            "sender_id": "c@upi",
            "receiver_id": "d@upi",
            "amount": 200.0,
            "timestamp": "2026-10-23T10:00:05Z",
        })
        + "\n",
        encoding="utf-8",
    )

    stats = producer.publish_file(file_path)
    assert stats["attempted"] == 3
    assert stats["delivered"] == 2
    assert stats["invalid"] == 1
    assert stats["failed"] == 0


def test_producer_publish_file_with_delivery_failure(tmp_path: Path):
    mock_prod = MagicMock()

    # Produce fails on delivery
    def mock_produce(topic, key, value, on_delivery):
        err = MagicMock()
        err.str.return_value = "Broker transport failure"
        err.code.return_value = KafkaError._TRANSPORT
        on_delivery(err, None)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    file_path = tmp_path / "fail_txs.jsonl"
    file_path.write_text(
        json.dumps({
            "transaction_id": "f_tx_fail",
            "sender_id": "a@upi",
            "receiver_id": "b@upi",
            "amount": 100.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })
        + "\n",
        encoding="utf-8",
    )

    stats = producer.publish_file(file_path)
    assert stats["attempted"] == 1
    assert stats["delivered"] == 0
    assert stats["failed"] == 1
    assert stats["invalid"] == 0


def test_producer_publish_file_with_limit(tmp_path: Path):
    mock_prod = MagicMock()

    def mock_produce(topic, key, value, on_delivery):
        msg = MagicMock()
        msg.topic.return_value = topic
        msg.partition.return_value = 0
        msg.offset.return_value = 1
        on_delivery(None, msg)

    mock_prod.produce.side_effect = mock_produce
    mock_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    producer = TransactionProducer(config=cfg, producer=mock_prod)

    file_path = tmp_path / "limit_txs.jsonl"
    lines = "\n".join([
        json.dumps({
            "transaction_id": f"tx_{i}",
            "sender_id": f"user_{i}@upi",
            "receiver_id": "receiver@upi",
            "amount": 100.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })
        for i in range(5)
    ]) + "\n"
    file_path.write_text(lines, encoding="utf-8")

    stats = producer.publish_file(file_path, limit=2)
    assert stats["attempted"] == 2
    assert stats["delivered"] == 2


# ---------------------------------------------------------------------------
# TransactionConsumer Tests
# ---------------------------------------------------------------------------


def test_consumer_normal_transaction_no_alert():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
    )

    tx = {
        "transaction_id": "tx_norm",
        "sender_id": "alice@upi",
        "receiver_id": "bob@upi",
        "amount": 500.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    msg = MockKafkaMessage(value=json.dumps(tx).encode("utf-8"), offset=10)

    result = consumer.process_message(msg)

    assert result is None  # Not suspicious
    # Alert producer must NOT be called
    mock_alert_prod.produce.assert_not_called()
    # Input message offset must be committed
    mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)


def test_consumer_high_value_transaction_generates_alert():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    def mock_alert_produce(topic, key, value, on_delivery):
        mock_msg = MagicMock()
        mock_msg.topic.return_value = topic
        mock_msg.partition.return_value = 0
        mock_msg.offset.return_value = 5
        on_delivery(None, mock_msg)

    mock_alert_prod.produce.side_effect = mock_alert_produce
    mock_alert_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
        alert_topic="fraud-alerts",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
    )

    tx = {
        "transaction_id": "tx_high_val",
        "sender_id": "whale@upi",
        "receiver_id": "escrow@upi",
        "amount": 250000.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    msg = MockKafkaMessage(value=json.dumps(tx).encode("utf-8"), offset=15)

    alert = consumer.process_message(msg)

    assert alert is not None
    assert alert["transaction_id"] == "tx_high_val"
    assert "HIGH_VALUE_TRANSACTION" in alert["risk_reasons"]

    # Verify alert was produced to fraud-alerts
    mock_alert_prod.produce.assert_called_once()
    call_args = mock_alert_prod.produce.call_args[1]
    assert call_args["topic"] == "fraud-alerts"
    assert call_args["key"] == b"tx_high_val"

    # Verify offset commit happened
    mock_consumer.commit.assert_called_once_with(message=msg, asynchronous=False)


def test_consumer_rapid_repeated_transfers_generates_alert():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    def mock_alert_produce(topic, key, value, on_delivery):
        mock_msg = MagicMock()
        mock_msg.topic.return_value = topic
        mock_msg.partition.return_value = 0
        mock_msg.offset.return_value = 1
        on_delivery(None, mock_msg)

    mock_alert_prod.produce.side_effect = mock_alert_produce
    mock_alert_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
    )

    sender = "burst_sender@upi"
    alerts = []
    for i in range(1, 6):
        tx = {
            "transaction_id": f"burst_{i}",
            "sender_id": sender,
            "receiver_id": f"receiver_{i}@upi",
            "amount": 1000.0,
            "timestamp": f"2026-10-23T10:00:{i*5:02d}Z",
        }
        msg = MockKafkaMessage(value=json.dumps(tx).encode("utf-8"), offset=i)
        res = consumer.process_message(msg)
        if res:
            alerts.append(res)

    # Exactly 1 alert generated (on 5th transfer)
    assert len(alerts) == 1
    assert alerts[0]["transaction_id"] == "burst_5"
    assert "RAPID_REPEATED_TRANSFERS" in alerts[0]["risk_reasons"]


def test_consumer_malformed_json_skip_and_commit():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
        poison_policy=PoisonPolicy.SKIP_AND_COMMIT,
    )

    bad_msg = MockKafkaMessage(value=b"{ invalid json ", offset=88)
    res = consumer.process_message(bad_msg)

    assert res is None
    # Must commit offset under SKIP_AND_COMMIT policy to clear poison pill
    mock_consumer.commit.assert_called_once_with(message=bad_msg, asynchronous=False)
    mock_alert_prod.produce.assert_not_called()


def test_consumer_malformed_json_raise_policy():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
        poison_policy=PoisonPolicy.RAISE,
    )

    bad_msg = MockKafkaMessage(value=b"not json", offset=99)
    with pytest.raises(Exception):
        consumer.process_message(bad_msg)


def test_consumer_alert_publish_failure_does_not_commit_input_offset():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    # Simulate alert produce error
    def mock_alert_produce(topic, key, value, on_delivery):
        err = MagicMock()
        err.str.return_value = "Kafka broker failure"
        err.code.return_value = -195
        on_delivery(err, None)

    mock_alert_prod.produce.side_effect = mock_alert_produce
    mock_alert_prod.flush.return_value = 0

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
    )

    fraud_tx = {
        "transaction_id": "tx_fraud_fail",
        "sender_id": "whale@upi",
        "receiver_id": "escrow@upi",
        "amount": 300000.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    msg = MockKafkaMessage(value=json.dumps(fraud_tx).encode("utf-8"), offset=20)

    # Processing should raise RuntimeError when alert publishing fails
    with pytest.raises(RuntimeError, match="Fraud alert delivery error"):
        consumer.process_message(msg)

    # CRITICAL: Input message offset must NOT be committed if alert publishing failed!
    mock_consumer.commit.assert_not_called()


def test_consumer_start_with_max_messages():
    mock_consumer = MagicMock()
    mock_alert_prod = MagicMock()

    tx = {
        "transaction_id": "poll_tx",
        "sender_id": "u1@upi",
        "receiver_id": "u2@upi",
        "amount": 100.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    msg = MockKafkaMessage(value=json.dumps(tx).encode("utf-8"), offset=1)
    mock_consumer.poll.return_value = msg

    cfg = KafkaConfig(
        bootstrap_servers="mock:9092",
        api_key="key",
        api_secret="secret",
    )
    consumer = TransactionConsumer(
        config=cfg,
        consumer=mock_consumer,
        alert_producer=mock_alert_prod,
    )

    count = consumer.start(max_messages=2)
    assert count == 2
    assert mock_consumer.poll.call_count == 2
    mock_consumer.close.assert_called_once()
    mock_alert_prod.flush.assert_called_once()
