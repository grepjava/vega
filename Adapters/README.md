# VegaAdapters

Vega's runtime metrics and slow polls, reported through
[swift-metrics](https://github.com/apple/swift-metrics) and
[swift-log](https://github.com/apple/swift-log). A package of its own, so
that Vega itself keeps no dependencies.

- `VegaSwiftMetrics`: `reportMetrics` samples `Runtime.metrics` and records
  it with whatever metrics backend the process bootstrapped.
- `VegaLogging`: `logSlowPolls` logs, through a `Logger`, each task poll that
  ran longer than a threshold (`Runtime.onSlowPoll`).

Inside Vega's repository the package builds against the Vega beside it;
on its own, against the Vega release.
