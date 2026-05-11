package logs

import (
	"io"
	"sync"
)

// Broker fans out log lines to all registered SSE subscribers.
type Broker struct {
	mu          sync.RWMutex
	subscribers map[chan string]struct{}
}

func NewBroker() *Broker {
	return &Broker{
		subscribers: make(map[chan string]struct{}),
	}
}

// Subscribe returns a channel that receives log lines. Call Unsubscribe when done.
func (b *Broker) Subscribe() chan string {
	ch := make(chan string, 256)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) Unsubscribe(ch chan string) {
	b.mu.Lock()
	delete(b.subscribers, ch)
	b.mu.Unlock()
	close(ch)
}

// Publish sends a line to all subscribers, dropping on full channels.
func (b *Broker) Publish(line string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
}

// Writer implements io.Writer so it can be passed as cmd.Stdout/Stderr.
type Writer struct {
	broker *Broker
	buf    []byte
}

func NewWriter(broker *Broker) *Writer {
	return &Writer{broker: broker}
}

func (w *Writer) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx == -1 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		w.broker.Publish(line)
	}
	return len(p), nil
}

var _ io.Writer = (*Writer)(nil)
