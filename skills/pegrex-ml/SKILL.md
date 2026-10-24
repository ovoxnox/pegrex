---
name: pegrex-ml
description: Verify ML graph equivalence after quantization or pruning with interval bounds plus concrete simulation. Use for model-deployment gates.
---

# ml graph verification

- `mlgraph.check_equivalence(g_float, g_quant, samples, quantized, eps)`:
  bound = sum(s/2) over quantized tensors; refuted if bound or any
  sample exceeds eps. Linear fragment only; conv2d refuses loudly.
