// +build OC_ENABLE !OC_DISABLE

package telemetry

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/costinm/wpgate/pkg/streams"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"go.opencensus.io/zpages"
)

// Adds about 1M extra to the binary
// Another ~1M  for zpages

// Right now only tracez and rpcz are available.
// rpcz tracks ocgrpc - Client/Server Completed,Sent,Received (Bytes/Messages)

// For HTTP, the wrapper adds:
// - trace
// - stats - wraps responseWriter
// - a context - private

// Agg: none, count, sum, dist, last
// 	m := stats.Int64("example.com/measure/openconns", "open connections", stats.UnitDimensionless)

// collects data and reports to exporters
//  if err := view.Register(&view.View{
//		Name:        "example.com/views/openconns",
//		Description: "open connections",
//		Measure:     m,
//		Aggregation: view.Distribution(0, 1000, 2000),
//	}

//	stats.Record(ctx, openConns.M(124))
func traceMap(r *http.Request) string {
	p := r.URL.Path
	// TODO: move to main
	if strings.HasPrefix(p, "/tcp/") {
		return "/tcp"
	}
	if strings.HasPrefix(p, "/dm/") {
		return "/dm"
	}

	return r.URL.Path
}


func init() {
	streams.MetricsHandlerWrapper = func(handler http.Handler) http.Handler {
		return &ochttp.Handler{Handler: handler}
	}
	streams.MetricsClientTransportWrapper = func(t http.RoundTripper) http.RoundTripper {
		return &ochttp.Transport{Base: t, FormatSpanName: traceMap}
	}

	// TODO: wrap client
	// TODO: wrapper for simpler zserge or oc
	// TODO: do we even need this ?
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.ProbabilitySampler(0.1)})
	//trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	// Span store:

	// default is 10 sec
	view.SetReportingPeriod(120 * time.Second)

	//exporter := &exporter.PrintExporter{}
	//view.RegisterExporter(exporter)
	//trace.RegisterExporter(exporter)

	if err := view.Register([]*view.View{
		ochttp.ServerRequestCountView,
		ochttp.ServerRequestBytesView,
		ochttp.ServerResponseBytesView,
		ochttp.ServerLatencyView,
		ochttp.ServerRequestCountByMethod,
		ochttp.ServerResponseCountByStatusCode,

		ochttp.ClientSentBytesDistribution,
		ochttp.ClientReceivedBytesDistribution,
		ochttp.ClientRoundtripLatencyDistribution,
	}...); err != nil {
		log.Println("Failed to register ochttp.DefaultServerViews")
	}

	view.Register(&view.View{
		Name:        "opencensus.io/http/client/completed_count",
		Measure:     ochttp.ClientRoundtripLatency,
		Aggregation: view.Count(),
		Description: "Count of completed requests, by HTTP method and response status",
		TagKeys:     []tag.Key{ochttp.KeyClientPath, ochttp.KeyClientStatus},
	})

	//pexporter, _ := prometheus.NewExporter(prometheus.Options{})
	//view.RegisterExporter(pexporter)

	//http.AddHandler("/metrics", pexporter)

	zpages.Handle(http.DefaultServeMux, "/debug/oc")

}
