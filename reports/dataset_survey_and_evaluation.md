# GatewayGuard 开源数据集评测报告（发布版，不含 OTIDS-2nd）

## 一、范围说明

本版报告基于 `2026-03-19` 的最新离线评测结果重写，发布口径中明确不展示 `OTIDS-2nd` 数据集表现。

本版正式纳入报告的结果来源：

- `reports/external_can_eval_iter2.json`
- `reports/external_can_eval_current_run.json`
- `reports/external_can_eval_iter2_diff.md`

本版排除项：

- `OTIDS-2nd`
- `RA8P1` 相关本地文件
- 本地真实流量采集
- 合成 / 混合 JSONL 单独测试文件

本版报告包含 `4` 个开源数据集、共 `15` 个 case。原始 JSON 评测文件仍保留完整结果，但本报告与发布对比结论均不引用 `OTIDS-2nd`。

## 二、评测口径

- 每个开源数据集单独训练一次检测器。
- 训练阶段使用该数据集的正常流量窗口。
- 测试阶段使用同数据集的 `normal_eval` 和攻击窗口。
- 大数据集按最多 `100000` 条训练、`100000` 条正常测试、`100000` 条攻击窗口评测。
- 指标重点看 `ML precision / recall / f1 / false_positive_rate`，`stock_alerts_total` 只表示系统总告警强度。

## 三、正常流量结果

| 数据集 | 样本数 | 唯一ID数 | 总告警 | Rule/Profile | ML | ML FPR | 主要告警类型 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B-CAN | 100000 | 180 | 520 | 515 | 5 | 0.0001 | payload_anomaly:481, temporal_anomaly:15, rpm_spike:8 |
| M-CAN | 100000 | 54 | 5 | 5 | 0 | 0.0000 | rpm_rate_anomaly:3, bus_load_anomaly:1, temporal_anomaly:1 |
| Car-Hacking | 100000 | 27 | 174 | 174 | 0 | 0.0000 | payload_anomaly:167, replay_suspected:6, bus_load_anomaly:1 |
| CAN-FD | 100000 | 54 | 36 | 36 | 0 | 0.0000 | payload_anomaly:29, gear_shift_anomaly:7 |

发布版正常流量结论：

- `4` 个纳入数据集的 `normal_eval` 全部维持原有水平，没有因为本轮调整引入新的正常集回归。
- `ML` 正常段误报仍然接近零，只有 `B-CAN normal_eval` 保留 `5` 条 `ML` 告警，对应 `FPR = 0.0001`。

## 四、攻击流量结果

| 数据集 | Case | 样本数 | 攻击数 | 总告警 | Rule/Profile | ML | Precision | Recall | F1 | 主要告警类型 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B-CAN | ddos_tail | 100000 | 16000 | 29084 | 14677 | 14407 | 0.9997 | 0.9001 | 0.9473 | payload_anomaly:14628, ml_auxiliary:14407 |
| B-CAN | fuzzing_tail | 100000 | 3000 | 4732 | 2208 | 2524 | 1.0000 | 0.8413 | 0.9138 | ml_auxiliary:2524, unknown_can_id:2031 |
| M-CAN | ddos_tail | 100000 | 37587 | 66168 | 32914 | 33254 | 1.0000 | 0.8847 | 0.9388 | ml_auxiliary:33254, unknown_id_flood:32906 |
| M-CAN | fuzzing_tail | 100000 | 11455 | 13603 | 3971 | 9632 | 1.0000 | 0.8409 | 0.9135 | ml_auxiliary:9632, unknown_can_id:3812 |
| Car-Hacking | dos_tail | 100000 | 23673 | 52133 | 28461 | 23672 | 1.0000 | 1.0000 | 1.0000 | ml_auxiliary:23672, unknown_id_flood:20107 |
| Car-Hacking | fuzzy_tail | 100000 | 12021 | 22499 | 11165 | 11334 | 0.9986 | 0.9415 | 0.9692 | ml_auxiliary:11334, payload_anomaly:9063 |
| Car-Hacking | rpm_tail | 100000 | 18952 | 26382 | 4447 | 20726 | 0.9144 | 1.0000 | 0.9553 | rpm_mode_anomaly:18952, rpm_rate_anomaly:2983 |
| Car-Hacking | gear_tail | 100000 | 18817 | 32061 | 8883 | 23178 | 0.8118 | 1.0000 | 0.8962 | gear_state_out_of_profile:18879, gear_shift_anomaly:4299 |
| CAN-FD | flooding | 100000 | 43070 | 85531 | 42462 | 43069 | 1.0000 | 1.0000 | 1.0000 | ml_auxiliary:43069, unknown_id_flood:42449 |
| CAN-FD | fuzzing | 100000 | 28156 | 84662 | 56484 | 28178 | 0.9984 | 0.9992 | 0.9988 | payload_anomaly:28285, ml_auxiliary:28178 |
| CAN-FD | malfunction | 100000 | 8212 | 61922 | 51841 | 10081 | 0.8125 | 0.9974 | 0.8955 | temporal_anomaly:10040, payload_anomaly:51809 |

## 五、当前版本结论

表现最强的场景：

- `Car-Hacking dos_tail`：`F1 = 1.0000`
- `CAN-FD flooding`：`F1 = 1.0000`
- `CAN-FD fuzzing`：`F1 = 0.9988`
- `Car-Hacking fuzzy_tail`：`F1 = 0.9692`
- `Car-Hacking rpm_tail`：`F1 = 0.9553`
- `B-CAN ddos_tail`：`F1 = 0.9473`

当前发布版里相对偏弱但已可用的场景：

- `CAN-FD malfunction`：`F1 = 0.8955`
- `Car-Hacking gear_tail`：`F1 = 0.8962`
- `B-CAN fuzzing_tail`：`F1 = 0.9138`
- `M-CAN fuzzing_tail`：`F1 = 0.9135`

整体结论：

- 发布版口径下，纳入报告的 `11` 个攻击 case 已全部具备有效 `ML F1`，不再存在 `Recall = 0` 的公开展示项。
- 不含 `OTIDS-2nd` 时，本轮发布版的攻击 case 加权 `weighted_f1 = 0.9617`。
- 本轮最有价值的修复是把 `B-CAN ddos_tail`、`CAN-FD malfunction`、`Car-Hacking rpm_tail`、`Car-Hacking gear_tail` 从“几乎不可用”拉回到可提交水平。

## 六、与上一轮发布口径关系

上一轮可对比基线使用的是：

- `reports/external_can_eval_current_run.json`

本轮发布版对比报告见：

- `reports/external_can_eval_iter2_diff.md`

对比结果在发布版口径下有三个重点：

- 正常流量 `4` 个数据集没有新增回归。
- 攻击 case 加权 `weighted_f1` 从 `0.8860` 提升到 `0.9617`。
- 主要增益集中在 `B-CAN ddos_tail`、`CAN-FD malfunction`、`Car-Hacking rpm_tail`、`Car-Hacking gear_tail` 四个原薄弱场景。
