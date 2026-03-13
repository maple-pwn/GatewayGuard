"""Profile-First CAN IDS Orchestration Layer

Architecture:
- ProfileManager learns baseline from normal traffic
- 4 specialized detectors: IDBehavior, TimingProfile, PayloadProfile, IForestAux
- AlertAggregator produces event-level output

Legacy logic preserved in anomaly_detector_old.py
"""

from typing import List, Tuple
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.config import settings
from app.services.profiles.can_profile import ProfileManager
from app.services.detectors.id_behavior_detector import IDBehaviorDetector
from app.services.detectors.timing_profile_detector import TimingProfileDetector
from app.services.detectors.payload_profile_detector import PayloadProfileDetector
from app.services.detectors.iforest_aux_detector import IForestAuxDetector
from app.services.aggregation.alert_aggregator import AlertAggregator, AggregatedEvent


class AnomalyDetectorService:
    """Profile-First CAN IDS 主服务"""

    def __init__(self):
        cfg = settings.detector

        self.profile_mgr = ProfileManager(min_packets_for_common=cfg.min_train_packets)

        self.id_detector = IDBehaviorDetector(
            self.profile_mgr, unknown_id_policy=cfg.unknown_id_policy
        )
        self.timing_detector = TimingProfileDetector(
            self.profile_mgr,
            window_size=cfg.temporal_window_size,
            burst_z_threshold=cfg.burst_z_threshold,
            gap_z_threshold=cfg.gap_z_threshold,
        )
        self.payload_detector = PayloadProfileDetector(self.profile_mgr)
        self.iforest_detector = IForestAuxDetector(
            contamination=cfg.iforest_contamination,
            enabled=cfg.enable_iforest_aux,
        )

        self.aggregator = AlertAggregator(time_window_ms=cfg.event_window_ms)
        self.is_trained = False

    def train(self, normal_packets: List[UnifiedPacket]):
        """Train Profile-First detectors"""
        if len(normal_packets) < settings.detector.min_train_packets:
            return

        self.profile_mgr.learn_from_normal(
            normal_packets, vehicle_name=settings.detector.vehicle_profile
        )

        if settings.detector.enable_iforest_aux:
            self.iforest_detector.fit(normal_packets)

        self.is_trained = True

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Execute detection - returns packet-level alerts"""
        if not self.is_trained:
            return []

        alerts = []
        alerts.extend(self.id_detector.detect(packets))
        alerts.extend(self.timing_detector.detect(packets))

        if settings.detector.enable_payload_profile:
            alerts.extend(self.payload_detector.detect(packets))

        if settings.detector.enable_iforest_aux:
            alerts.extend(self.iforest_detector.detect(packets))

        alerts.sort(key=lambda a: a.confidence, reverse=True)
        return alerts

    def detect_with_aggregation(
        self, packets: List[UnifiedPacket]
    ) -> Tuple[List[AnomalyEvent], List[AggregatedEvent]]:
        """Detection with event aggregation"""
        alerts = self.detect(packets)
        if not settings.detector.enable_event_aggregation:
            return alerts, []
        events = self.aggregator.aggregate(alerts)
        self._attach_event_metadata(alerts, events)
        return alerts, events

    @staticmethod
    def _attach_event_metadata(
        alerts: List[AnomalyEvent], events: List[AggregatedEvent]
    ) -> None:
        if not alerts or not events:
            return

        epsilon = 1e-6
        for alert in alerts:
            node = alert.target_node or alert.source_node
            for event in events:
                if alert.anomaly_type != event.anomaly_type:
                    continue
                if node and node not in event.involved_ids:
                    continue
                if not (
                    event.first_seen - epsilon
                    <= alert.timestamp
                    <= event.last_seen + epsilon
                ):
                    continue

                alert.event_id = event.event_id
                alert.packet_count = event.packet_count
                break
