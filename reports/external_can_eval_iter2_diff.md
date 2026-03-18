# 外部评测差异报告（发布版，不含 OTIDS-2nd）

## 1. 对比对象

- 旧结果：`reports/external_can_eval_current_run.json`
- 新结果：`reports/external_can_eval_iter2.json`

本对比报告明确排除 `OTIDS-2nd`，只统计发布版纳入展示的 `4` 个开源数据集。

## 2. 总体变化

- 共同 case 数：`15`
- 总告警量变化：`+69517`
- Rule/Profile 告警变化：`-19`
- ML 告警变化：`+69536`
- ML 指标发生变化的 case 数：`4`

发布版攻击 case 加权指标变化：

- `weighted_f1`：`0.8860 -> 0.9617`
- 具有有效 `ML F1` 的攻击 case 数：`8 -> 11`

告警总量增幅最大的 4 个 case：

- `Car-Hacking / gear_tail`：`+23169`
- `Car-Hacking / rpm_tail`：`+21919`
- `B-CAN / ddos_tail`：`+14400`
- `CAN-FD / malfunction`：`+10029`

## 3. 正常流量差异

| 数据集 | 旧总告警 | 新总告警 | 差值 | 旧 Rule | 新 Rule | 旧 ML | 新 ML |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B-CAN | 520 | 520 | +0 | 515 | 515 | 5 | 5 |
| M-CAN | 5 | 5 | +0 | 5 | 5 | 0 | 0 |
| Car-Hacking | 174 | 174 | +0 | 174 | 174 | 0 | 0 |
| CAN-FD | 36 | 36 | +0 | 36 | 36 | 0 | 0 |

结论：

- 发布版口径下，所有 `normal_eval` 都保持不变。
- 本轮优化没有引入新的正常集误报回归。

## 4. 攻击流量差异

### 4.1 指标发生变化的 case

| 数据集 | Case | 旧 ML | 新 ML | 旧 Precision | 新 Precision | 旧 Recall | 新 Recall | 旧 F1 | 新 F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| B-CAN | ddos_tail | 7 | 14407 | 0.2857 | 0.9997 | 0.0001 | 0.9001 | 0.0002 | 0.9473 |
| Car-Hacking | rpm_tail | 0 | 20726 | - | 0.9144 | 0.0000 | 1.0000 | - | 0.9553 |
| Car-Hacking | gear_tail | 0 | 23178 | - | 0.8118 | 0.0000 | 1.0000 | - | 0.8962 |
| CAN-FD | malfunction | 58 | 10081 | 0.0000 | 0.8125 | 0.0000 | 0.9974 | - | 0.8955 |

### 4.2 保持稳定的主力 case

| 数据集 | Case | F1 旧值 | F1 新值 |
| --- | --- | ---: | ---: |
| M-CAN | ddos_tail | 0.9388 | 0.9388 |
| M-CAN | fuzzing_tail | 0.9135 | 0.9135 |
| Car-Hacking | dos_tail | 1.0000 | 1.0000 |
| Car-Hacking | fuzzy_tail | 0.9692 | 0.9692 |
| CAN-FD | flooding | 1.0000 | 1.0000 |
| CAN-FD | fuzzing | 0.9988 | 0.9988 |
| B-CAN | fuzzing_tail | 0.9138 | 0.9138 |

## 5. 逐 case 告警类型变化

### B-CAN / ddos_tail

- `ml_auxiliary`: `7 -> 14407`，已从几乎失效恢复到可用状态

### Car-Hacking / rpm_tail

- `rpm_mode_anomaly`: `8 -> 18952`
- `rpm_rate_anomaly`: `8 -> 2983`

### Car-Hacking / gear_tail

- `gear_state_out_of_profile`: `1 -> 18879`
- `gear_shift_anomaly`: `8 -> 4299`

### CAN-FD / malfunction

- `temporal_anomaly`: `11 -> 10040`

## 6. 发布版结论

这次发布版和上一轮相比，变化不是“普遍微调”，而是对先前公开口径里最弱的 `4` 个场景完成了集中修复，同时保持了原本已经很强的主力 case 不退化。

如果只看发布版口径，当前版本的核心结论是：

- 正常流量稳定
- 主力强项稳定
- 原弱项已基本补齐
- 发布版里不再保留 `Recall = 0` 的公开展示 case
