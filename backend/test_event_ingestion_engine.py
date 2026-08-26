"""Tests for High-Throughput Event Ingestion Engine."""

import pytest
from event_ingestion_engine import (
    EventIngestionEngine,
    GrpcBlockchainSubscriber,
    KafkaProducer,
    KafkaConsumerGroup,
    BlockEvent,
    KafkaMessage,
)


@pytest.fixture
def engine():
    return EventIngestionEngine()


class TestGrpcBlockchainSubscriber:
    def test_init(self):
        sub = GrpcBlockchainSubscriber("evm", "ws://localhost:8546")
        assert sub.chain == "evm"
        assert sub.endpoint == "ws://localhost:8546"

    def test_stop(self):
        sub = GrpcBlockchainSubscriber("evm", "ws://localhost:8546")
        sub._running = True
        sub.stop()
        assert not sub._running


class TestKafkaProducer:
    def test_produce(self):
        producer = KafkaProducer()
        msg = KafkaMessage(key="test", value={"data": 1}, topic="test_topic")
        producer.produce(msg)
        stats = producer.get_stats()
        assert stats["buffered_messages"] == 1

    def test_flush(self):
        producer = KafkaProducer()
        for i in range(5):
            producer.produce(KafkaMessage(key=f"k{i}", value={"i": i}, topic="t"))
        count = producer.flush()
        assert count == 5
        assert producer.get_stats()["buffered_messages"] == 0


class TestKafkaConsumerGroup:
    def test_init(self):
        consumer = KafkaConsumerGroup("test_topic", "test_group", num_workers=2)
        assert consumer.topic == "test_topic"
        assert consumer.num_workers == 2

    def test_register_handler(self):
        consumer = KafkaConsumerGroup("t", "g")
        consumer.register_handler(lambda x: None)
        assert len(consumer._handlers) == 1


class TestEventIngestionEngine:
    def test_init(self, engine):
        summary = engine.get_summary()
        assert summary["subscribers"] == 0

    def test_add_subscriber(self, engine):
        sub = engine.add_subscriber("evm", "ws://localhost:8546")
        assert "evm" in engine.subscribers

    def test_add_consumer(self, engine):
        consumer = engine.add_consumer("block_events_evm", "evm_group")
        assert "block_events_evm" in engine.consumers

    def test_ingest_event(self, engine):
        event = BlockEvent(
            block_number=12345,
            block_hash="0xabc",
            timestamp=1000.0,
            chain="evm",
            transactions=[{"hash": "0x123"}],
        )
        engine.ingest_event(event)
        stats = engine.get_summary()
        assert stats["producer"]["buffered_messages"] == 1
