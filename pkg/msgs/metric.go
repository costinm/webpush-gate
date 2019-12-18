package msgs

import _ "expvar"

// Metric is an interface for applications updating metrics
// Expvar is an interface between metric and the collection system.
type Metric interface {
	Add(float64)
}

type MetricProvider interface {
	Metric(string) Metric
}
