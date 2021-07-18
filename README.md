# Linux Telemetry

**The Double Slit Experiment**

Taken from an [interesting physics anomaly](https://en.wikipedia.org/wiki/Double-slit_experiment) where the behavior of a physical system mutates simply by being observed.

The thesis behind the project is that meaningful well thought out telemetry could change the behavior of broader systems.

---

# About

This is a library of abstractions build around Go and eBPF code. 

The library will aggregate events from the Linux kernel at runtime using [eBPF](https://ebpf.io/).

The abstractions are `ObservationPoint`'s. These are aggregate systems in Go built around [tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html) in the Linux kernel.

 - ProcessExecuted _An event for every process executed on the system_
 - ContainerEvent _An event for any new container (docker, kubernetes, etc) started on the system_
 - SocketStateChange _An event for any change in a socket on the system_
 - SignalDelivered _An event for every Linux signal delivered to a process on the system_

Each `ObservationPoint` returns one or more events that each implement the `Event` interface.

```go 
// Event is a generic event for all
// ObservationPoint systems.
type Event interface {
	JSON() ([]byte, error)
	String() string
	Name() string
}
```

