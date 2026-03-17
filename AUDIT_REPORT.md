# GatewayGuard RPM/GEAR/Replay Detection Capability Audit

**Date**: 2026-03-16  
**Objective**: Assess current detection capabilities for RPM, GEAR, and Replay attacks before implementing targeted improvements

---

## 1. CURRENT CODE AUDIT

### 1.1 Existing Detector Architecture

**Detection Chain** (from `anomaly_detector.py`):
1. **IDBehaviorDetector** - Unknown ID, frequency anomalies
2. **TimingProfileDetector** - Temporal pattern detection
3. **PayloadProfileDetector** - Data pattern analysis (optional)
4. **IForestAuxDetector** - ML-based auxiliary (optional)

**Current Strengths**:
- ✅ DoS/Flooding detection (burst, rate anomalies)
- ✅ Unknown ID detection
- ✅ DLC anomalies
- ✅ Bus-level timing/load anomalies
- ✅ Payload byte statistics (entropy, stability, constant detection)

**Current Weaknesses for RPM/GEAR/Replay**:
- ❌ No sequence freshness tracking (replay detection)
- ❌ No counter/monotonic field detection (replay prevention)
- ❌ No cross-ID correlation analysis (RPM/GEAR context)
- ❌ No state transition modeling (semantic consistency)
- ❌ Limited multi-packet sequence analysis

### 1.2 Profile System Analysis

**IDProfile** (from `can_profile.py`) currently tracks:
- Gap statistics: median, std, p10, p90
- Payload statistics: constant_ratio, zero_ff_ratio, entropy, unique_ratio
- Byte-level: min, max, mean, std, stability_mask
- Value deltas: mean, std (first 2 bytes only)
- Repeat ratio, payload change metrics

**Extension Points Identified**:
- ✅ Value delta tracking exists but limited to 2-byte words
- ❌ No state bucket modeling
- ❌ No transition profile tracking
- ❌ No counter position detection
- ❌ No cross-ID relationship storage

### 1.3 Temporal State Tracking

**TemporalState** (from `timing_profile_detector.py`):
- Uses `deque()` for sliding windows
- Tracks: gaps, payload_changes, value_deltas, repeat_flags
- Maintains previous packet state: prev_ts, prev_payload, prev_word

**Capabilities**:
- ✅ Window-based sequence analysis
- ✅ Previous state comparison
- ❌ No long-term sequence history
- ❌ No subsequence fingerprinting
- ❌ No freshness/age tracking

---

## 2. GAP ANALYSIS FOR RPM/GEAR/REPLAY

### 2.1 Why Current System Struggles

**RPM Attacks** (Engine speed manipulation):
- Legitimate ID, legitimate DLC
- Values may be within statistical range
- **Missing**: Cross-ID context (RPM should correlate with throttle, gear, speed)
- **Missing**: State transition validation (sudden RPM changes need context)

**GEAR Attacks** (Gear position manipulation):
- Legitimate ID, legitimate timing
- **Missing**: State transition rules (gear can't jump 1→5 instantly)
- **Missing**: Cross-ID validation (gear must match speed/RPM)

**Replay Attacks** (Message replay):
- Legitimate everything - ID, DLC, timing, payload statistics
- **Missing**: Sequence freshness detection
- **Missing**: Counter field tracking
- **Missing**: Subsequence reuse detection

### 2.2 Required New Capabilities

**For Replay Detection**:
1. Subsequence fingerprinting (rolling hash)
2. Counter/monotonic field detection
3. Sequence age/freshness tracking
4. Window-level similarity detection

**For RPM/GEAR Detection**:
1. Cross-ID correlation mining (automatic)
2. Consistency profile learning
3. State transition validation
4. Context-aware anomaly scoring

---

## 3. EVALUATION DATASET REFERENCES

From `evaluate_external_can_datasets.py`:
- Line 637: `"rpm_tail": lambda: iter_car_hacking_attack(car_zip, "RPM_dataset.csv")`
- Line 681: `"replay_segment": make_otids_attack_segment_factory(otids_zip, otids_inner, "Replay")`

**Available Test Data**:
- ✅ RPM attack dataset (Car-Hacking dataset)
- ✅ Replay attack dataset (OTIDS)
- ❓ GEAR attack dataset (need to verify availability)

---

## 4. IMPLEMENTATION STRATEGY

### 4.1 New Detector: ReplaySequenceDetector

**Responsibilities**:
- Detect repeated subsequences (rolling hash)
- Track counter-like byte positions
- Monitor sequence freshness/age
- Identify stale pattern reuse

**Evidence Types**:
- `repeated_subsequence`
- `counter_rollback`
- `stale_pattern_reuse`
- `freshness_violation`

### 4.2 New Detector: CrossIDContextDetector

**Responsibilities**:
- Mine ID correlations during training
- Learn consistency profiles
- Validate cross-ID context during detection
- Detect unsupported value changes

**Evidence Types**:
- `cross_id_inconsistency`
- `lag_relation_violation`
- `state_transition_mismatch`
- `unsupported_value_change`

### 4.3 Profile Extensions

**Add to IDProfile**:
```python
# State modeling
state_buckets: Dict[str, StateBucket] = field(default_factory=dict)
transition_profile: Dict[Tuple[str, str], float] = field(default_factory=dict)

# Counter detection
counter_positions: List[int] = field(default_factory=list)
counter_monotonic_ratio: float = 0.0

# Enhanced deltas
delta_sign_ratio: Dict[str, float] = field(default_factory=dict)  # up/down/flat
value_histogram: Dict[int, int] = field(default_factory=dict)
```

---

## 5. INTEGRATION PLAN

**New Detection Chain**:
1. IDBehaviorDetector (existing)
2. TimingProfileDetector (existing)
3. PayloadProfileDetector (existing)
4. **ReplaySequenceDetector** (NEW)
5. **CrossIDContextDetector** (NEW)
6. IForestAuxDetector (existing, optional)

**Design Principles**:
- ✅ Preserve profile-first architecture
- ✅ Maintain time-ordered processing
- ✅ Keep detectors independent and composable
- ✅ Provide interpretable evidence
- ✅ Don't break existing DoS/Flooding detection

---

## 6. NEXT STEPS

1. ✅ **Phase 1 Complete**: Code audit and gap analysis
2. ⏳ **Phase 2**: Implement ReplaySequenceDetector
3. ⏳ **Phase 3**: Implement CrossIDContextDetector
4. ⏳ **Phase 4**: Extend profile system
5. ⏳ **Phase 5**: Integration and testing
6. ⏳ **Phase 6**: Evaluation on RPM/GEAR/Replay datasets
7. ⏳ **Phase 7**: Documentation updates

---

**Status**: Ready to proceed with implementation
