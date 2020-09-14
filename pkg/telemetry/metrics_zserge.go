package telemetry

import (
	"expvar"
	"net/http"
	"runtime"
	"time"

	"github.com/costinm/wpgate/pkg/streams"
	"github.com/zserge/metric"
)

// zserge is a very small package for metrics with self-contained graph interface.
// openCensus may provide similar interface

// Modifications to zserge:
// - add NewInt - to make it easy to convert from expvar ( more can be added )
// - reset for counter

// TODO: modify zserge to mimic expvar interface ( autoregister, etc)
// TODO: modify zserge to mimic and maybe include OC or Prom interface

var (
	goroutines = metric.NewGauge("15m30s")
	goalloc    = metric.NewGauge("15m30s")
	goalloct   = metric.NewGauge("15m30s")
)

func init() {
	// Requires publishing metrics in expvar
	http.Handle("/debug/metrics", metric.Handler(metric.Exposed))

	//"2ms1s", "1h1m"

	// Some Go internal metrics
	expvar.Publish("go:numgoroutine", goroutines)
	//expvar.Publish("go:numcgocall", metric.NewGauge("2ms1s", "15m30s", "1h1m"))
	expvar.Publish("go:alloc", goalloc)
	expvar.Publish("go:alloctotal", goalloct)

	go func() {
		for range time.Tick(500 * time.Millisecond) {
			m := &runtime.MemStats{}
			runtime.ReadMemStats(m)
			goroutines.Add(float64(runtime.NumGoroutine()))
			//expvar.Get("go:numcgocall").(metric.Metric).Add(float64(runtime.NumCgoCall()))
			//expvar.Get("go:alloc").(metric.Metric)...
			goalloc.Add(float64(m.Alloc) / 1000000)
			goalloct.Add(float64(m.TotalAlloc) / 1000000)
		}
	}()

	streams.Metrics = &zsergeProvider{}
}

type zsergeProvider struct {
}

func (*zsergeProvider) NewCounter(name, descr string, frames ...string) streams.Metric {
	g := metric.NewCounter(frames...)
	expvar.Publish(name, g)
	return g
}

func (*zsergeProvider) NewGauge(name, descr string, frames ...string) streams.Metric {
	g := metric.NewGauge(frames...)
	expvar.Publish(name, g)
	return g
}

func (*zsergeProvider) NewHistogram(name, descr string, frames ...string) streams.Metric {
	g := metric.NewHistogram(frames...)
	expvar.Publish(name, g)
	return g
}
