"""Configuration for RingShield Kafka streaming."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class KafkaConfig:
    bootstrap_servers: str
    api_key: str
    api_secret: str
    input_topic: str
    alert_topic: str

    @classmethod
    def from_env(cls) -> "KafkaConfig":
        required = [
            "KAFKA_BOOTSTRAP_SERVERS",
            "KAFKA_API_KEY",
            "KAFKA_API_SECRET",
            "KAFKA_INPUT_TOPIC",
            "KAFKA_ALERT_TOPIC",
        ]

        missing = [name for name in required if not os.getenv(name)]

        if missing:
            raise RuntimeError(
                "Missing required environment variables: "
                + ", ".join(missing)
            )

        return cls(
            bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"],
            api_key=os.environ["KAFKA_API_KEY"],
            api_secret=os.environ["KAFKA_API_SECRET"],
            input_topic=os.environ["KAFKA_INPUT_TOPIC"],
            alert_topic=os.environ["KAFKA_ALERT_TOPIC"],
        )

    def client_config(self) -> dict[str, str]:
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "security.protocol": "SASL_SSL",
            "sasl.mechanisms": "PLAIN",
            "sasl.username": self.api_key,
            "sasl.password": self.api_secret,
        }