// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

type privacyProcessor struct{ config Config }

func (p *privacyProcessor) sanitizer() *sanitizer {
	return &sanitizer{config: p.config, remaining: p.config.MaxCollectionItems}
}

func (p *privacyProcessor) cleanMap(m pcommon.Map)    { p.sanitizer().attributes(m) }
func (p *privacyProcessor) cleanText(v string) string { return p.sanitizer().text(v, 0) }

func (p *privacyProcessor) cleanScope(scope pcommon.InstrumentationScope) {
	scope.SetName(p.cleanText(scope.Name()))
	scope.SetVersion(p.cleanText(scope.Version()))
	p.cleanMap(scope.Attributes())
}

func (p *privacyProcessor) processLogs(_ context.Context, data plog.Logs) (plog.Logs, error) {
	resources := data.ResourceLogs()
	for i := 0; i < resources.Len(); i++ {
		r := resources.At(i)
		p.cleanMap(r.Resource().Attributes())
		r.SetSchemaUrl(p.cleanText(r.SchemaUrl()))
		for j := 0; j < r.ScopeLogs().Len(); j++ {
			s := r.ScopeLogs().At(j)
			p.cleanScope(s.Scope())
			s.SetSchemaUrl(p.cleanText(s.SchemaUrl()))
			for k := 0; k < s.LogRecords().Len(); k++ {
				record := s.LogRecords().At(k)
				p.cleanMap(record.Attributes())
				record.SetSeverityText(p.cleanText(record.SeverityText()))
				record.SetEventName(p.cleanText(record.EventName()))
				if p.config.LogBodyMode == "strict" {
					record.Body().SetStr(mask)
				} else {
					p.sanitizer().valueInPlace(record.Body(), 0, "")
				}
			}
		}
	}
	return data, nil
}

func (p *privacyProcessor) processTraces(_ context.Context, data ptrace.Traces) (ptrace.Traces, error) {
	resources := data.ResourceSpans()
	for i := 0; i < resources.Len(); i++ {
		r := resources.At(i)
		p.cleanMap(r.Resource().Attributes())
		r.SetSchemaUrl(p.cleanText(r.SchemaUrl()))
		for j := 0; j < r.ScopeSpans().Len(); j++ {
			s := r.ScopeSpans().At(j)
			p.cleanScope(s.Scope())
			s.SetSchemaUrl(p.cleanText(s.SchemaUrl()))
			for k := 0; k < s.Spans().Len(); k++ {
				span := s.Spans().At(k)
				span.SetName(p.cleanText(span.Name()))
				span.Status().SetMessage(p.cleanText(span.Status().Message()))
				p.cleanMap(span.Attributes())
				// Opaque vendor tracestate is not needed for trace/span correlation.
				// Drop it rather than exporting unknown embedded credentials.
				span.TraceState().FromRaw("")
				for n := 0; n < span.Events().Len(); n++ {
					e := span.Events().At(n)
					e.SetName(p.cleanText(e.Name()))
					p.cleanMap(e.Attributes())
				}
				if !p.config.PreserveSpanLinks {
					span.Links().RemoveIf(func(ptrace.SpanLink) bool { return true })
				} else {
					for n := 0; n < span.Links().Len(); n++ {
						link := span.Links().At(n)
						p.cleanMap(link.Attributes())
						link.TraceState().FromRaw("")
					}
				}
			}
		}
	}
	return data, nil
}

func (p *privacyProcessor) cleanExemplars(exemplars pmetric.ExemplarSlice) {
	for i := 0; i < exemplars.Len(); i++ {
		p.cleanMap(exemplars.At(i).FilteredAttributes())
	}
}

func (p *privacyProcessor) processMetrics(_ context.Context, data pmetric.Metrics) (pmetric.Metrics, error) {
	resources := data.ResourceMetrics()
	for i := 0; i < resources.Len(); i++ {
		r := resources.At(i)
		p.cleanMap(r.Resource().Attributes())
		r.SetSchemaUrl(p.cleanText(r.SchemaUrl()))
		for j := 0; j < r.ScopeMetrics().Len(); j++ {
			s := r.ScopeMetrics().At(j)
			p.cleanScope(s.Scope())
			s.SetSchemaUrl(p.cleanText(s.SchemaUrl()))
			for k := 0; k < s.Metrics().Len(); k++ {
				metric := s.Metrics().At(k)
				name := p.cleanText(metric.Name())
				if name != metric.Name() {
					name = "elven.redacted.metric"
				}
				metric.SetName(name)
				metric.SetDescription(p.cleanText(metric.Description()))
				unit := p.cleanText(metric.Unit())
				if unit != metric.Unit() {
					unit = "1"
				}
				metric.SetUnit(unit)
				p.cleanMap(metric.Metadata())
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					dps := metric.Gauge().DataPoints()
					for n := 0; n < dps.Len(); n++ {
						p.cleanMap(dps.At(n).Attributes())
						p.cleanExemplars(dps.At(n).Exemplars())
					}
				case pmetric.MetricTypeSum:
					dps := metric.Sum().DataPoints()
					for n := 0; n < dps.Len(); n++ {
						p.cleanMap(dps.At(n).Attributes())
						p.cleanExemplars(dps.At(n).Exemplars())
					}
				case pmetric.MetricTypeHistogram:
					dps := metric.Histogram().DataPoints()
					for n := 0; n < dps.Len(); n++ {
						p.cleanMap(dps.At(n).Attributes())
						p.cleanExemplars(dps.At(n).Exemplars())
					}
				case pmetric.MetricTypeExponentialHistogram:
					dps := metric.ExponentialHistogram().DataPoints()
					for n := 0; n < dps.Len(); n++ {
						p.cleanMap(dps.At(n).Attributes())
						p.cleanExemplars(dps.At(n).Exemplars())
					}
				case pmetric.MetricTypeSummary:
					dps := metric.Summary().DataPoints()
					for n := 0; n < dps.Len(); n++ {
						p.cleanMap(dps.At(n).Attributes())
					}
				}
			}
		}
	}
	return data, nil
}
