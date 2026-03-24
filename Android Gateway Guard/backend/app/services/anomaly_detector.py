"""Profile-First CAN IDS Orchestration Layer

Architecture:
- ProfileManager learns baseline from normal traffic
- 7 specialized detectors:
    Profile-based: IDBehavior, TimingProfile, PayloadProfile, IForestAux
    Signal-level:  RPMDetector, GearDetector
    Sequence-level: ReplaySequenceDetector
- AlertAggregator produces event-level output

Legacy logic preserved in anomaly_detector_old.py
"""

from typing import Dict, List, Tuple
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.config import settings
from app.services.profiles.can_profile import ProfileManager
from app.services.detectors.id_behavior_detector import IDBehaviorDetector
from app.services.detectors.timing_profile_detector import TimingProfileDetector
from app.services.detectors.payload_profile_detector import PayloadProfileDetector
from app.services.detectors.iforest_aux_detector import IForestAuxDetector
from app.services.detectors.replay_sequence_detector import ReplaySequenceDetector
from app.services.detectors.rpm_detector import RPMDetector
from app.services.detectors.gear_detector import GearDetector
from app.services.detectors.powertrain_signal_utils import discover_powertrain_ids

from app.services.aggregation.alert_aggregator import AlertAggregator, AggregatedEvent


class AnomalyDetectorService:
    """Profile-First CAN IDS 主服务"""

    def __init__(self):
        self._init_components()

    def _init_components(self) -> None:
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
        self.replay_detector = ReplaySequenceDetector()
        self.rpm_detector = RPMDetector()
        self.gear_detector = GearDetector()
        self.aggregator = AlertAggregator(time_window_ms=cfg.event_window_ms)
        self.is_trained = False

    def reset(self):
        """Reset detector state (for testing)"""
        self._init_components()

    def train(self, normal_packets: List[UnifiedPacket]):
        """Train Profile-First detectors - packets must be chronologically sorted"""
        if len(normal_packets) < settings.detector.min_train_packets:
            return

        # Verify chronological order
        sorted_packets = sorted(normal_packets, key=lambda p: p.timestamp)

        self.profile_mgr.learn_from_normal(
            sorted_packets, vehicle_name=settings.detector.vehicle_profile
        )

        resolved_rpm_id, resolved_gear_id = discover_powertrain_ids(
            sorted_packets,
            settings.detector.rpm_can_id,
            settings.detector.gear_can_id,
            max_rpm=self.rpm_detector.max_rpm,
            context_window_s=max(
                self.rpm_detector.context_window_s,
                self.gear_detector.context_window_s,
            ),
        )
        self.rpm_detector.rpm_can_id = resolved_rpm_id
        self.rpm_detector.gear_can_id = resolved_gear_id
        self.gear_detector.rpm_can_id = resolved_rpm_id
        self.gear_detector.gear_can_id = resolved_gear_id
        ignored_payload_ids = set()
        if settings.detector.enable_rpm_detector and resolved_rpm_id:
            ignored_payload_ids.add(resolved_rpm_id)
        if settings.detector.enable_gear_detector and resolved_gear_id:
            ignored_payload_ids.add(resolved_gear_id)
        self.payload_detector.ignored_msg_ids = ignored_payload_ids

        if settings.detector.enable_iforest_aux:
            self.iforest_detector.fit(normal_packets)

        if settings.detector.enable_replay_detector:
            self.replay_detector.fit(sorted_packets)

        if settings.detector.enable_rpm_detector:
            self.rpm_detector.fit(sorted_packets)

        if settings.detector.enable_gear_detector:
            self.gear_detector.fit(sorted_packets)

        self.is_trained = True

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Execute detection - returns packet-level alerts"""
        if not self.is_trained:
            raise RuntimeError(
                "Detector not trained. Call train() first or use POST /api/anomaly/train"
            )

        sorted_packets = sorted(packets, key=lambda packet: packet.timestamp)
        alerts = []
        alerts.extend(self.id_detector.detect(sorted_packets))
        alerts.extend(self.timing_detector.detect(sorted_packets))

        if settings.detector.enable_payload_profile:
            alerts.extend(self.payload_detector.detect(sorted_packets))

        if settings.detector.enable_iforest_aux:
            alerts.extend(self.iforest_detector.detect(sorted_packets))

        if settings.detector.enable_replay_detector:
            alerts.extend(self.replay_detector.detect(sorted_packets))

        if settings.detector.enable_rpm_detector:
            alerts.extend(self.rpm_detector.detect(sorted_packets))

        if settings.detector.enable_gear_detector:
            alerts.extend(self.gear_detector.detect(sorted_packets))

        alerts = self._promote_profile_ml_alerts(
            alerts,
            total_packets=len(sorted_packets),
        )
        alerts = self._cull_duplicate_alerts(alerts)
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

    @staticmethod
    def _alert_priority(alert: AnomalyEvent) -> Tuple[int, float]:
        severity_rank = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }.get(alert.severity, 0)
        return severity_rank, alert.confidence

    @staticmethod
    def _alert_signature(alert: AnomalyEvent) -> str:
        if alert.anomaly_type == "payload_anomaly":
            rules = []
            for item in alert.evidence or []:
                if not isinstance(item, dict):
                    continue
                rule = item.get("rule")
                if rule and rule != "byte_profile_context":
                    rules.append(str(rule))
            if rules:
                return "|".join(sorted(set(rules)))

        if alert.anomaly_type == "replay_suspected":
            for item in alert.evidence or []:
                if isinstance(item, str) and item:
                    return item

        return ""

    @staticmethod
    def _timing_gap_ratio(alert: AnomalyEvent) -> float:
        for item in alert.evidence or []:
            if not isinstance(item, dict) or item.get("rule") != "burst_ratio":
                continue
            return float(item.get("gap_ratio", 0.0))
        return 0.0

    @staticmethod
    def _is_rpm_semantic_ml_candidate(alert: AnomalyEvent) -> bool:
        return (
            alert.detection_method == "rpm_semantic_profile"
            and alert.anomaly_type
            in {
                "rpm_mode_anomaly",
                "rpm_rate_anomaly",
                "rpm_gear_mismatch",
            }
        )

    @staticmethod
    def _is_gear_semantic_ml_candidate(alert: AnomalyEvent) -> bool:
        return (
            alert.detection_method == "gear_semantic_profile"
            and alert.anomaly_type
            in {
                "gear_state_out_of_profile",
                "gear_shift_anomaly",
            }
        )

    @classmethod
    def _is_timing_ml_candidate(cls, alert: AnomalyEvent) -> bool:
        if alert.detection_method != "timing_profile":
            return False

        gap_ratio = cls._timing_gap_ratio(alert)
        has_robust_gap = any(
            isinstance(item, dict) and item.get("rule") == "robust_gap_mad"
            for item in alert.evidence or []
        )
        return has_robust_gap or gap_ratio >= 8.0

    @classmethod
    def _promote_profile_ml_alerts(
        cls,
        alerts: List[AnomalyEvent],
        total_packets: int,
    ) -> List[AnomalyEvent]:
        if not alerts or total_packets <= 0:
            return alerts

        rpm_candidates = [
            alert for alert in alerts if cls._is_rpm_semantic_ml_candidate(alert)
        ]
        gear_candidates = [
            alert for alert in alerts if cls._is_gear_semantic_ml_candidate(alert)
        ]
        timing_candidates = [
            alert for alert in alerts if cls._is_timing_ml_candidate(alert)
        ]
        iforest_count = sum(
            1 for alert in alerts if alert.detection_method == "iforest_auxiliary"
        )

        rpm_count = len(rpm_candidates)
        gear_count = len(gear_candidates)
        timing_count = len(timing_candidates)

        promote_rpm = (
            rpm_count >= max(128, total_packets // 500)
            and rpm_count / total_packets >= 0.05
            and rpm_count >= max(gear_count * 2, 128)
        )
        promote_gear = (
            gear_count >= max(128, total_packets // 500)
            and gear_count / total_packets >= 0.10
            and gear_count >= max(rpm_count * 2, 128)
        )
        promote_timing = (
            timing_count >= max(128, total_packets // 1000)
            and timing_count / total_packets >= 0.003
            and iforest_count < max(128, int(total_packets * 0.04))
            and not promote_rpm
            and not promote_gear
        )

        if promote_rpm:
            for alert in rpm_candidates:
                alert.detection_method = "ml_rpm_semantic_profile"

        if promote_gear:
            for alert in gear_candidates:
                alert.detection_method = "ml_gear_semantic_profile"

        if promote_timing:
            for alert in timing_candidates:
                alert.detection_method = "ml_timing_profile"

        return alerts

    @staticmethod
    def _alert_cooldown_seconds(base_cooldown_s: float, alert: AnomalyEvent) -> float:
        multiplier = 1.0
        if alert.detection_method == "payload_profile":
            multiplier = AnomalyDetectorService._payload_profile_cooldown_multiplier(
                alert
            )
        elif alert.detection_method in {
            "ml_rpm_semantic_profile",
            "ml_gear_semantic_profile",
            "ml_timing_profile",
        }:
            multiplier = 0.0
        elif alert.detection_method == "replay_sequence":
            multiplier = AnomalyDetectorService._replay_sequence_cooldown_multiplier(
                alert
            )
        elif alert.detection_method == "id_behavior_unknown_flood":
            multiplier = 0.0
        elif alert.detection_method == "iforest_auxiliary":
            multiplier = 1.0
            for item in alert.evidence or []:
                if not isinstance(item, dict) or item.get("rule") != "iforest_context":
                    continue
                is_unknown = not bool(item.get("known_id", True))
                burst_signal = bool(item.get("burst_signal", False))
                zero_ff_flag = bool(item.get("zero_ff_flag", False))
                repeat_run = int(item.get("repeat_run", 0))
                id_window_share = float(item.get("id_window_share", 0.0))
                id_rate_ratio = float(item.get("id_rate_ratio", 0.0))
                global_rate_ratio = float(item.get("global_rate_ratio", 0.0))
                if burst_signal:
                    if (
                        not is_unknown
                        and zero_ff_flag
                        and repeat_run >= 4
                        and id_window_share >= 0.45
                        and global_rate_ratio >= 2.0
                        and id_rate_ratio >= 6.0
                    ):
                        multiplier = 0.0
                    else:
                        multiplier = 0.1 if is_unknown else 0.25
                elif is_unknown and zero_ff_flag and (
                    repeat_run >= 2 or id_window_share >= 0.05
                ):
                    multiplier = 0.0
                elif is_unknown:
                    multiplier = 0.25
                else:
                    multiplier = 1.0
                break
        return base_cooldown_s * multiplier

    @staticmethod
    def _payload_profile_cooldown_multiplier(alert: AnomalyEvent) -> float:
        multiplier = 10.0
        baseline_repeat_ratio = None
        for item in alert.evidence or []:
            if not isinstance(item, dict) or item.get("rule") != "byte_profile_context":
                continue
            baseline_repeat_ratio = float(item.get("baseline_repeat_ratio", 0.0))
            break

        for item in alert.evidence or []:
            if not isinstance(item, dict):
                continue

            rule = item.get("rule")
            if rule == "constant_payload":
                return 0.0

            if rule == "byte_stability_violation":
                total_violations = int(item.get("total_violations", 0))
                max_deviation = int(item.get("max_deviation", 0))
                if baseline_repeat_ratio is not None and baseline_repeat_ratio >= 0.8:
                    continue
                if total_violations >= 3 or max_deviation >= 24:
                    return 0.0
                if total_violations >= 2 and max_deviation >= 12:
                    multiplier = min(multiplier, 0.02)
            elif rule == "byte_statistical_range":
                total_violations = int(item.get("total_violations", 0))
                max_deviation = float(item.get("max_deviation", 0.0))
                if baseline_repeat_ratio is not None and baseline_repeat_ratio >= 0.8:
                    continue
                if total_violations >= 4 or max_deviation >= 48.0:
                    return 0.0
                if (
                    (total_violations >= 3 and max_deviation >= 20.0)
                    or (total_violations >= 2 and max_deviation >= 32.0)
                ):
                    multiplier = min(multiplier, 0.02)
            elif rule == "entropy_drift":
                entropy_z = float(item.get("entropy_z", 0.0))
                if entropy_z >= 8.0:
                    multiplier = min(multiplier, 0.05)

        return multiplier

    @staticmethod
    def _replay_sequence_cooldown_multiplier(alert: AnomalyEvent) -> float:
        for item in alert.evidence or []:
            if not isinstance(item, str):
                continue
            if item == "exact_payload_reuse":
                return 0.0
            if item == "stale_pattern_reuse":
                return 0.5
            break
        return 10.0

    def _cull_duplicate_alerts(
        self, alerts: List[AnomalyEvent]
    ) -> List[AnomalyEvent]:
        if len(alerts) <= 1:
            return alerts

        cooldown_s = max(settings.detector.alert_cooldown_ms, 0.0) / 1000.0
        if cooldown_s <= 0:
            return alerts

        kept: List[AnomalyEvent] = []
        clusters: Dict[Tuple[str, str, str, str, str], Tuple[int, float]] = {}

        for alert in sorted(alerts, key=lambda item: item.timestamp):
            node = alert.target_node or alert.source_node or ""
            signature = self._alert_signature(alert)
            key = (
                alert.protocol or "",
                alert.anomaly_type,
                alert.detection_method,
                node,
                signature,
            )
            packet_span = max(alert.packet_count, 1)
            effective_cooldown_s = self._alert_cooldown_seconds(cooldown_s, alert)

            if key not in clusters:
                alert.packet_count = packet_span
                kept.append(alert)
                clusters[key] = (len(kept) - 1, alert.timestamp)
                continue

            kept_idx, cluster_last_seen = clusters[key]
            existing = kept[kept_idx]

            if alert.timestamp - cluster_last_seen > effective_cooldown_s:
                alert.packet_count = packet_span
                kept.append(alert)
                clusters[key] = (len(kept) - 1, alert.timestamp)
                continue

            combined_count = max(existing.packet_count, 1) + packet_span
            if self._alert_priority(alert) > self._alert_priority(existing):
                alert.packet_count = combined_count
                kept[kept_idx] = alert
            else:
                existing.packet_count = combined_count
            clusters[key] = (kept_idx, alert.timestamp)

        return kept
