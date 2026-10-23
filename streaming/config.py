"""Configuration for RingShield Kafka streaming with Confluent Cloud."""

from dataclasses import dataclass
import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class KafkaConfig:
    """Connection parameters for Confluent Cloud Kafka."""

    bootstrap_servers: str
    api_key: str
    api_secret: str
    input_topic: str = "upi-transactions"
    alert_topic: str = "fraud-alerts"
    group_id: str = "ringshield-fraud-detection"

    @classmethod
    def from_env(
        cls,
        input_topic: str | None = None,
        alert_topic: str | None = None,
        group_id: str | None = None,
    ) -> "KafkaConfig":
        """Load and validate Kafka configuration from environment variables.

        Fails early with a sanitized error if required credentials are missing.
        Never prints or logs the API secret.
        """
        required = [
            "KAFKA_BOOTSTRAP_SERVERS",
            "KAFKA_API_KEY",
            "KAFKA_API_SECRET",
        ]

        missing = [name for name in required if not os.getenv(name)]
        if missing:
            raise RuntimeError(
                "Missing required Kafka configuration environment variable(s): "
                + ", ".join(missing)
                + ". Set them in .env or your shell environment."
            )

        resolved_input = (
            input_topic
            or os.getenv("KAFKA_INPUT_TOPIC")
            or "upi-transactions"
        )
        resolved_alert = (
            alert_topic
            or os.getenv("KAFKA_ALERT_TOPIC")
            or "fraud-alerts"
        )
        resolved_group = (
            group_id
            or os.getenv("KAFKA_GROUP_ID")
            or "ringshield-fraud-detection"
        )

        return cls(
            bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"].strip(),
            api_key=os.environ["KAFKA_API_KEY"].strip(),
            api_secret=os.environ["KAFKA_API_SECRET"].strip(),
            input_topic=resolved_input.strip(),
            alert_topic=resolved_alert.strip(),
            group_id=resolved_group.strip(),
        )

    def client_config(
        self, extra_config: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Generate librdkafka client configuration dict with SASL_SSL authentication."""
        conf: dict[str, Any] = {
            "bootstrap.servers": self.bootstrap_servers,
            "security.protocol": "SASL_SSL",
            "sasl.mechanisms": "PLAIN",
            "sasl.username": self.api_key,
            "sasl.password": self.api_secret,
        }
        if extra_config:
            conf.update(extra_config)
        return conf

    def masked_summary(self) -> dict[str, str]:
        """Return a sanitized configuration summary safe for logging."""
        masked_key = (
            f"{self.api_key[:2]}****{self.api_key[-2:]}"
            if len(self.api_key) >= 4
            else "******"
        )
        server_host = self.bootstrap_servers.split(":")[0]
        return {
            "bootstrap_server": server_host,
            "api_key": masked_key,
            "input_topic": self.input_topic,
            "alert_topic": self.alert_topic,
            "group_id": self.group_id,
        }