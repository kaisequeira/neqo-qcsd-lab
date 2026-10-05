# One collection action

The public `run` command and direct `run_campaign` API own one temporary
validated-facts scope before loading a campaign. Nested qualification readers
borrow this scope. Their original validator still runs for the first exact
reference in the action.

The owner binds the campaign file before parsing, checks dependencies after
waiting for a study lock, binds the complete copied `inputs` tree, and reopens
registered bytes, modes and membership immediately before collection and before
reporting success. Mutable result directories are not immutable input trees.

A prospective qualification authority and canary bridge record exactly three
control units: `cli.main`'s direct `run` branch, `orchestrator.run_campaign`, and
`orchestrator._run_loaded_campaign`. All other CLI branches and orchestration
units remain protected, including sample planning, input materialization,
collection, response acceptance, traffic and Native primitives. Historical
delivery readers and already published authorities retain their old meaning.

HOST tests use controlled original qualification/runtime and collector
boundaries. Installation, a fresh current authority, installed checks and actual
capture remain separate Root operations. These tests claim no measured speedup,
Native fix or additional accepted traces.
