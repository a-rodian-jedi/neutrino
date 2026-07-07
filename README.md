# Neutrino

Neutrino is an experimental, high-performance eBPF-based Endpoint Detection and Response (EDR) agent. The primary purpose of this application is to demonstrate system-level event tracing (such as process executions and network connections) while adhering to strict performance constraints in Go.

## Architecture Pattern

The system follows a highly concurrent, decoupled pipeline pattern to ensure the kernel event ingestion is never blocked by slower I/O operations:

1. **eBPF Monitors:** C-based eBPF programs trace kernel events (e.g., `execve`, `tcp_connect`) and write directly to a ring buffer.
2. **Zero-Alloc Hot Path:** Go reads raw event bytes off the kernel ring buffer, maps them directly to memory using `unsafe.Pointer`, and fires pointers to recycled struct instances into a central communications channel.
3. **Worker Pool & Enrichment:** A pool of background workers pulls raw events off the channel, enriches them (such as safely converting raw byte arrays to Go strings without allocating in the hot path), and serializes them.
4. **Data Shipping:** Enriched events are published to a Redis Pub/Sub channel for downstream alerting or storage. 

## Performance Highlights

A primary design constraint in Neutrino was to achieve **zero heap allocations** per event read in the agent's hot path. The Go garbage collector can introduce unacceptable latency (GC pauses) if high-frequency kernel events continuously allocate objects. 

By utilizing `unsafe.Pointer` casting in combination with a `sync.Pool` to recycle event instances, the per-event ingestion overhead is drastically minimized. 

### Benchmarks

Below is a comparison of decoding events using standard `binary.Read` vs. the zero-allocation approach leveraging `unsafe.Pointer`. 

| Benchmark | Operations | ns/op | B/op | allocs/op |
| :--- | :--- | :--- | :--- | :--- |
| **DecodeExecEvent** (Raw to Struct) | 349,992 | 3415 ns/op | 336 B/op | 2 allocs/op |
| **RunHotPathWithBinaryRead** | 324,636 | 3606 ns/op | 720 B/op | 3 allocs/op |
| **RunHotPathWithUnsafePointer** | **44,252,791** | **26.14 ns/op** | **0 B/op** | **0 allocs/op** |

The transition from a safe reflection-based read to pointer casting completely eliminates loop allocations, decreasing event processing latency from **~3.6 microseconds** per event to **~26 nanoseconds** per event—an approximate 138x speedup.

## Future Bottlenecks & Roadmap

With the ingestion hot-path optimized to a zero-allocation baseline, the next architectural bottleneck will be lock contention on the central Go channel (`chan *event.Event`). 

As the number of eBPF monitors (Producers) and Publisher workers (Consumers) scales up, the MPMC (Multi-Producer, Multi-Consumer) demands on a single native Go channel's internal mutex will introduce measurable wait times. 

**Proposed solutions to scale beyond this bottleneck:**
- Sharding events across multiple channels to split contention.
- Transitioning the central event bus to a lock-free, atomic ring buffer data structure such as [go-disruptor](https://github.com/smartystreets-prototypes/go-disruptor) or [fast-mpmc](https://github.com/tylertreat/FastMPMC).
