# GatewayGuard Profile-First Refactoring Summary

## Completed: Profile-First CAN IDS Architecture

### What Changed

**From:** Rule + Isolation Forest + fixed whitelist
**To:** Profile-first temporal detection with modular architecture

### New Architecture

```
services/
  profiles/
    can_profile.py              # CANProfile, IDProfile, ProfileManager
  detectors/
    id_behavior_detector.py     # Unknown ID, DLC, burst detection
    timing_profile_detector.py  # Primary temporal detector
    payload_profile_detector.py # Per-ID payload modeling
    iforest_aux_detector.py     # Demoted auxiliary detector
  aggregation/
    alert_aggregator.py         # Event-level output
  anomaly_detector.py           # Lightweight orchestrator (52 lines)
```

### Key Improvements

1. **Profile-First Detection**
   - Learns from normal traffic instead of fixed VALID_CAN_IDS
   - Per-ID temporal modeling (gap, frequency, payload patterns)
   - Three policies: strict_profile, warmup_profile, open_world

2. **Modular Detectors**
   - IDBehaviorDetector: Unknown IDs, DLC anomalies, burst frequency
   - TimingProfileDetector: Main detector for temporal deviations
   - PayloadProfileDetector: Per-ID payload profiling
   - IForestAuxDetector: Optional auxiliary (disabled by default)

3. **Event Aggregation**
   - Groups packet-level alerts into events
   - Time-window based clustering (default 1000ms)
   - Reduces alert noise

4. **New Config Options**
   ```yaml
   detector:
     unknown_id_policy: "strict_profile"  # strict_profile | warmup_profile | open_world
     enable_iforest: false                # IForest demoted to auxiliary
     enable_payload_profile: true
     event_window_ms: 1000.0
     min_train_packets: 10
     burst_z_threshold: 4.0
     temporal_window_size: 8
     vehicle_profile: "default"
     profile_dir: "./profiles"
   ```

5. **Enhanced Models**
   - AnomalyEvent: Added event_id, packet_count, vehicle_profile, evidence
   - AnomalyEventORM: Extended with event-level fields

6. **API Compatibility**
   - `/api/anomaly/detect?with_aggregation=true` for event-level output
   - Backward compatible with existing packet-level queries

### Files Modified

- `services/anomaly_detector.py` - Reduced from 607 to 52 lines (orchestrator only)
- `config.py` - Added 10 new detector config options
- `models/anomaly.py` - Extended with event-level fields
- `routers/anomaly.py` - Added aggregation support

### Files Created

- `services/profiles/can_profile.py` (130 lines)
- `services/detectors/id_behavior_detector.py` (95 lines)
- `services/detectors/timing_profile_detector.py` (85 lines)
- `services/detectors/payload_profile_detector.py` (45 lines)
- `services/detectors/iforest_aux_detector.py` (90 lines)
- `services/aggregation/alert_aggregator.py` (65 lines)

### Old Code Preserved

- `services/anomaly_detector_old.py` - Original 607-line implementation

### Migration Notes

**Training Required:**
```python
detector.train(normal_packets, vehicle_name="my_vehicle")
```

**Detection:**
```python
# Packet-level
alerts = detector.detect(packets)

# Event-level
alerts, events = detector.detect_with_aggregation(packets)
```

**Policy Selection:**
- `strict_profile`: Only known IDs allowed (high security)
- `warmup_profile`: Only common IDs (>= min_train_packets)
- `open_world`: All IDs allowed (low false positives)

### What's NOT Changed

- Frontend remains compatible
- Database schema extended (backward compatible)
- LLM integration unchanged
- Simulator/collector unchanged
- UnifiedPacket abstraction unchanged

### Next Steps (TODO)

1. Test with real CAN datasets
2. Tune burst_z_threshold and gap_z_threshold
3. Add profile persistence (save/load from profile_dir)
4. Extend payload profiling with byte-level masks
5. Add profile comparison for multi-vehicle scenarios
6. Database migration for new columns

### Risk Assessment

**Low Risk:**
- Modular architecture allows easy rollback
- Old code preserved in anomaly_detector_old.py
- API backward compatible
- Graceful degradation if profile not trained

**Medium Risk:**
- Database schema changes require migration
- Performance impact of per-ID profiling (mitigated by efficient numpy ops)

**Mitigation:**
- Start with `unknown_id_policy="open_world"` for gradual rollout
- Monitor detection latency
- Use `enable_iforest=false` to reduce overhead
