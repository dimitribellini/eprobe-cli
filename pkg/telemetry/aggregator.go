package telemetry

import (
	"eprobe/pkg/registry"
	"sort"
	"sync"
)

// Aggregator handles aggregation for the Top view
type Aggregator struct {
	counts map[string]float64
	mu     sync.RWMutex
}

// NewAggregator creates a new thread-safe Aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		counts: make(map[string]float64),
	}
}

// Update increments the internal counters based on the provided event and rules
func (a *Aggregator) Update(event map[string]interface{}, rules []registry.AggregateHint) {
	if len(rules) == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, rule := range rules {
		if rule.Type == "count" {
			if val, ok := event[rule.Field]; ok {
				var keyStr string
				switch v := val.(type) {
				case string:
					keyStr = v
				default:
					continue // only group by string fields for now or convert to string if we want
				}
				cleanKey := sanitizeString(keyStr)
				a.counts[cleanKey]++
			}
		}
		// Implement other aggregation types if needed
	}
}

// AggregationResult represents a single row in the top view
type AggregationResult struct {
	Key   string
	Value float64
}

// Top returns the top limit results sorted descending by value
func (a *Aggregator) Top(limit int) []AggregationResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var results []AggregationResult
	for k, v := range a.counts {
		results = append(results, AggregationResult{Key: k, Value: v})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Value > results[j].Value
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results
}

// Reset clears the counters
func (a *Aggregator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counts = make(map[string]float64)
}
