from collections import defaultdict
from dataclasses import dataclass
from typing import List
from app.models.anomaly import AnomalyEvent


@dataclass
class AggregatedEvent:
    event_id: str
    first_seen: float
    last_seen: float
    packet_count: int
    involved_ids: List[str]
    anomaly_type: str
    severity: str
    confidence: float
    evidence: List[str]
    detection_method: str


class AlertAggregator:
    def __init__(self, time_window_ms: float = 1000.0):
        self.window = time_window_ms / 1000.0

    def aggregate(self, alerts: List[AnomalyEvent]) -> List[AggregatedEvent]:
        if not alerts:
            return []

        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        groups = defaultdict(list)

        for alert in sorted_alerts:
            key = (alert.anomaly_type, alert.target_node or alert.source_node)
            groups[key].append(alert)

        events = []
        event_counter = 0

        for (anom_type, node), group in groups.items():
            i = 0
            while i < len(group):
                cluster = [group[i]]
                j = i + 1
                while (
                    j < len(group)
                    and (group[j].timestamp - cluster[0].timestamp) <= self.window
                ):
                    cluster.append(group[j])
                    j += 1

                if len(cluster) >= 1:
                    event_counter += 1
                    first = cluster[0]
                    last = cluster[-1]
                    ids = list(set(a.target_node or a.source_node for a in cluster))
                    total_packets = sum(max(a.packet_count, 1) for a in cluster)
                    weighted_conf = sum(
                        a.confidence * max(a.packet_count, 1) for a in cluster
                    )
                    avg_conf = weighted_conf / max(total_packets, 1)
                    max_sev = max(
                        cluster,
                        key=lambda a: {
                            "critical": 4,
                            "high": 3,
                            "medium": 2,
                            "low": 1,
                        }.get(a.severity, 0),
                    ).severity
                    evidence = [a.description for a in cluster[:5]]

                    events.append(
                        AggregatedEvent(
                            event_id=f"evt_{event_counter:06d}",
                            first_seen=first.timestamp,
                            last_seen=last.timestamp,
                            packet_count=total_packets,
                            involved_ids=ids,
                            anomaly_type=anom_type,
                            severity=max_sev,
                            confidence=round(avg_conf, 3),
                            evidence=evidence,
                            detection_method=first.detection_method,
                        )
                    )

                i = j

        return events
