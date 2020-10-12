package streams

import (
	"net/http"
)

// Abstract the metric collection

// Goals:
// - OC can be used, but also lighter alternatives like expvar
// - test use regular code can access the real value of the metrics (like SNMP/jmx)

// Unlike OC and like expvar, creating a metric also exposes it.

// expvar defines expvar.Var - which returns the json string of the metric, and Publish adds it to the handler
// it doesn't define interface for setting the value.
// Built-in are Int,Float,Map,String - with Value, Add, Set (but not interface)
// 'Do' interface, 'Get'

// zserge has a Metric interface - Add(float64)/String
// they can be exposed via expvar or a map returning snapshot. Nice built-in svg graph

// oc uses the term Measure (interface - but only desc) and Measurement (struct - float64 based, int converted)
// pattern is M() Measurement

// Overhead:
// expvar: struct{float64}, atomic.Store, sync.Map
// zserge: counter=float64, gauge=sync+4float+int, hist(float+bins*2float)
//        timeseries: samples, metric, interval
// oc: view==timeseries

// Export format:
// expvar: /debug/vars json map
//
// prom: /metrics
// # HELP opencensus_io_http_server_latency Latency distribution of HTTP requests
// # TYPE opencensus_io_http_server_latency histogram
// opencensus_io_http_server_latency_bucket{le="0"} 0
// opencensus_io_http_server_latency_sum 7.105802572142727e+08
// opencensus_io_http_server_latency_count 6965

var (
	// Will be set by one of the metrics options to wrap a handler and transport
	MetricsHandlerWrapper func(http.Handler) http.Handler

	MetricsClientTransportWrapper func(tripper http.RoundTripper) http.RoundTripper
)

// TODO: auto-expose expvar ( see zserge )

// Metric is an interface for applications updating metrics
// Expvar is an interface between metric and the collection system.
type Metric interface {
	Add(float64)
}

// Set of metrics used by client or server of a service.
type ServiceMetrics struct {
	// Active requests, gauge.
	Active Metric

	// Total requests, counter
	Total  Metric
	Errors Metric

	// Service latency (total).
	Latency Metric
}

var (
	collect = "1h5m"
)

func NewServiceMetrics(base string, descr string) *ServiceMetrics {
	return &ServiceMetrics{
		Active:  Metrics.NewGauge(base+":active", descr+" active", collect),
		Total:   Metrics.NewCounter(base+":total", descr+" total", collect),
		Errors:  Metrics.NewCounter(base+":errors", descr+" errors", collect),
		Latency: Metrics.NewHistogram(base+":lat", descr+" latency", "15m30s", "2h5m"),
	}
}

// Abstract creation of metrics - zserge(minimal with UI) for local, prom or OC for servers.
// The opts are currently used for in-process time-series. If specified and an in-process implementation
// exists it'll be used. The parameter is 'total' and 'interval' - total/interval is the number of samples.
// External timeseries have their own polling interval and aggregation.
// If metrics are pushed, the first interval is used to control the rate.
type MetricProvider interface {

	// Can only go up. Current value tracked.
	NewCounter(name, descr string, opts ...string) Metric

	// Like counter, but can go down. Mean, min, max ( and sum, count) are tracked.
	NewGauge(name, descr string, opts ...string) Metric

	// Tracks 50, 90, 99% value of all Add events.
	NewHistogram(name, descr string, opts ...string) Metric
}

var (
	// Singleton factory
	Metrics MetricProvider = &NoMetrics{}
)

type NoMetrics struct {
}

func (*NoMetrics) NewCounter(name, descr string, labels ...string) Metric {
	return &emptyMetric{}
}

func (*NoMetrics) NewGauge(name, descr string, labels ...string) Metric {
	return &emptyMetric{}
}

func (*NoMetrics) NewHistogram(name, descr string, labels ...string) Metric {
	return &emptyMetric{}
}

type emptyMetric struct {
}

func (*emptyMetric) Add(float64) {}

// From go-kit - has multiple implementations ( no direct dependency on go-kit, but could be passed)

//// Counter describes a metric that accumulates values monotonically.
//// An example of a counter is the number of received HTTP requests.
//type Counter interface {
//	With(labelValues ...string) Counter
//	Add(delta float64)
//}
//
//// Gauge describes a metric that takes specific values over time.
//// An example of a gauge is the current depth of a job queue.
//type Gauge interface {
//	With(labelValues ...string) Gauge
//	Set(value float64)
//	Add(delta float64)
//}
//
//// Histogram describes a metric that takes repeated observations of the same
//// kind of thing, and produces a statistical summary of those observations,
//// typically expressed as quantiles or buckets. An example of a histogram is
//// HTTP request latencies.
//type Histogram interface {
//	With(labelValues ...string) Histogram
//	Observe(value float64)
//}
