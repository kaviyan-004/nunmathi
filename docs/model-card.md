# Traffic model card

Generated from `traffic.get_model().card` (also `GET /api/model-card`, and *View → Model Card* in the UI).

- **Model:** HistGradientBoostingClassifier (250 iters, 31 leaves) (`nm-traffic-2`)
- **Classes:** voip, video, web, chat, email
- **Window:** 5.0 s of ESP packets (per direction lengths & timings after subtracting inferred ESP overhead)
- **Training data:** synthetic (forge.traffic_models) through randomized ESP geometries
- **Geometries randomised in training:** encr 20 / integ 0; encr 12 / integ 2; encr 12 / integ 12; encr 12 / integ 14; encr 3 / integ 2; encr 28 / integ 0; encr 11 / integ 2; encr 11 / integ 12; encr 13 / integ 12
- **Split:** 3508 train / 1179 calibration / 1174 test windows (independent seeds)
- **Held-out synthetic test accuracy:** 0.994, macro-F1 0.9942
- **Conformal prediction:** split-conformal, α = 0.1; empirical coverage 0.994, mean set size 1.0
- **Out-of-distribution:** mean 5-NN distance in standardized feature space; threshold = 2.545 (0.99 quantile of calibration)

## Confusion matrix (rows = truth, columns = predicted)

| | voip | video | web | chat | email |
|---|---|---|---|---|---|
| **voip** | 235 | 0 | 0 | 1 | 0 |
| **video** | 0 | 236 | 1 | 0 | 0 |
| **web** | 0 | 2 | 231 | 0 | 1 |
| **chat** | 0 | 0 | 0 | 233 | 0 |
| **email** | 0 | 1 | 1 | 0 | 232 |

## Features

`up_log_pkts`, `up_log_bytes`, `up_len_mean`, `up_len_std`, `up_len_p10`, `up_len_p50`, `up_len_p90`, `up_frac_large`, `up_frac_small`, `up_log_iat_mean`, `up_iat_cv`, `up_periodicity`, `down_log_pkts`, `down_log_bytes`, `down_len_mean`, `down_len_std`, `down_len_p10`, `down_len_p50`, `down_len_p90`, `down_frac_large`, `down_frac_small`, `down_log_iat_mean`, `down_iat_cv`, `down_periodicity`, `pkt_ratio_up`, `byte_ratio_up`, `log_iat_p50_all`, `iat_cv_all`, `max_burst_100ms`, `active_frac`, `len_distinct_frac`, `log_rate_pps`, `dir_switch_rate`, `bytes_skew`

## Validation on real IPsec traffic

Real tunnels were captured between two strongSwan 6.0.7 gateways in rootless Linux network namespaces, with application traffic sent through the tunnel in labelled 30 s phases (voip, web, video, chat). Every 5 s window lying inside one phase was scored.

| Capture set | Windows | Top-1 accuracy |
|---|---|---|
| 4 tunnels (AES-GCM + ML-KEM, AES-CBC, IKEv1 3DES, ESP-NULL), first traffic profile | 82 | 0.988 |
| 1 tunnel, second traffic profile (other codec, frame rate, object sizes, phase order) | 38 | 1.000 |
| Both sets, 3 extra training seeds | 120 | 0.983 – 0.992 |

How to read these numbers:

- **The first model version scored only 0.46 on the first set.** Web and video were swapped, because the synthetic data had no UDP real-time video and no plain-HTTP fetches. The generators were widened with those realistic variants (plus constant-bitrate voice codecs and realistic idle-mail behaviour). The second profile was recorded **after** that change, as a check that it was not tuned to the first set.
- **The lab traffic is simple.** Scripted voip, HTTP downloads, a UDP video stream and a UDP chat echo, over one fast link. **Email was not exercised on real traffic.** Accuracy on production traffic (browsers, real apps, WAN loss and jitter) is still unmeasured and will be lower.
- **Under real traffic the conformal sets are still size 1.** Coverage was calibrated on synthetic data and is not guaranteed under distribution shift, so treat the sets as indicative.

## Limitations

- Trained only on synthetic traffic; accuracy on real captures will be lower and should be re-measured with labelled local data.
- Windows with fewer than 4 packets are treated as idle and not classified.
- Class set is closed (voip, video, web, chat, email); anything else should surface as OOD or as a large prediction set.

## Metadata Exposure Index (MEI)

Per window: MEI = (log₂K − H) / log₂K, where H is the entropy of the classifier's probability vector over the K = 5 classes. 1 means the window's application class is fully readable from ESP sizes and timings; 0 means the output is uniform. The tunnel reports the mean and 90th percentile. NM-150 is raised as Low when the mean MEI is ≥ 0.8 and as Informational when it is ≥ 0.5, unless TFC padding is observed (see `docs/rules.md`).
