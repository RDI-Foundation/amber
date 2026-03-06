<!-- amber-docs
summary: Wire the tau2 environment, evaluator, agent, and LiteLLM adapters into one scenario.
-->

# tau2

This scenario wires the tau2 environment, two LiteLLM-backed routes, a tau2 evaluator, and a
tau2 agent into a benchmark-style multi-component graph.

## Files

- `scenario.json5`: root manifest that connects the environment, evaluators, routers, and agent.
- `tau2.json5`: tau2 environment component.
- `tau2-evaluator.json5`: evaluator component with domain and trial-count config.
- `tau2-agent.json5`: agent component that consumes an LLM slot and exposes an A2A endpoint.
- `litellm.json5`, `litellm-proxy.json5`, `litellm-wrapper.json5`: LiteLLM adapter stack that
  exposes both LLM and admin APIs to the evaluator and agent.
