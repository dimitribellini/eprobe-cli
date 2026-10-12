package telemetry

import "sync"

// EventBuffer is a thread-safe circular buffer for telemetry events
type EventBuffer struct {
	events []map[string]interface{}
	head   int
	tail   int
	count  int
	size   int
	mu     sync.RWMutex
}

// NewEventBuffer creates a new EventBuffer with a fixed capacity
func NewEventBuffer(size int) *EventBuffer {
	return &EventBuffer{
		events: make([]map[string]interface{}, size),
		size:   size,
	}
}

// Push adds a new event to the circular buffer
func (b *EventBuffer) Push(event map[string]interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events[b.head] = event
	b.head = (b.head + 1) % b.size
	if b.count < b.size {
		b.count++
	} else {
		b.tail = (b.tail + 1) % b.size
	}
}

// Get returns the event at the given index from oldest to newest.
// Index 0 is the oldest event.
func (b *EventBuffer) Get(index int) map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if index < 0 || index >= b.count {
		return nil
	}

	actualIndex := (b.tail + index) % b.size
	return b.events[actualIndex]
}

// GetAll returns all current events in the buffer from oldest to newest
func (b *EventBuffer) GetAll() []map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]map[string]interface{}, b.count)
	for i := 0; i < b.count; i++ {
		actualIndex := (b.tail + i) % b.size
		result[i] = b.events[actualIndex]
	}
	return result
}

// Len returns the number of events currently in the buffer
func (b *EventBuffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}
