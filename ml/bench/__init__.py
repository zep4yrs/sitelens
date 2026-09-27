"""EXP-1004：本地小决策模型 vs 传统 ML 基线对比（预注册实验）。

协议与采纳闸门见 PRE_REGISTRATION.md（先于任何决策模型运行提交）。
模块分工：
  build_eval_sets.py         三个任务的固定评测集（seed=20260928）+ sha256 清单
  metrics_shared.py          基线与 LM 共用的同一指标实现
  eval_baselines_same_sets.py 持久化基线模型在同集上重算
  eval_decision_model.py     llama.cpp 类型化决策读出（digit/choice logprob）
"""
