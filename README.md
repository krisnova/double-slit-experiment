# Runtime Linux and Container Telemetry 

**The Double Slit Experiment**

Taken from an [interesting physics anomaly](https://en.wikipedia.org/wiki/Double-slit_experiment) where the behavior of a physical system mutates simply by being observed.

The thesis behind the project is that meaningful well thought out telemetry could change the behavior of broader systems.

---

# About

This is a library of abstractions build around Go and eBPF code. 

The library will aggregate events from the Linux kernel at runtime using [eBPF](https://ebpf.io/).

The abstractions are `ObservationPoint`'s. These are aggregate systems in Go built around [tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html) in the Linux kernel.

Each `ObservationPoint` is defined by a function name, and each implements the `Event` interface.

```go 
type Event interface {
	JSON() ([]byte, error)
	String() string
	Code() int
	Name() string
}
```

### ProcessExecuted Observation Point

The library can send an event whenever a process is executed globally on a Linux system.

```go
// ProcessExecuted will aggregate tracepoint data from the kernel
// and send a generic Event back over a channel.
func ProcessExecuted(ch chan Event) {
	ch <- evt // Send events back out over the channel
}
```


