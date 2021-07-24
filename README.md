# Linux Telemetry

**The Double Slit Experiment**

Taken from an [interesting physics anomaly](https://en.wikipedia.org/wiki/Double-slit_experiment) where the behavior of a physical system mutates simply by being observed.

The thesis behind the project is that meaningful well thought out telemetry could change the behavior of broader systems.

---

# Install

```bash 
git clone git@github.com:kris-nova/double-slit-experiment.git
cd double-slit-experiment
make
./dse --help
```

# Running

```bash
./dse run | uniq
```

**Note**: See `userspace/profile.go` for filters and configuration for now.

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

# Filters

The Double Slit Experiment has two types of filters that can be applied to various Observation Points.

 - SelectFunction() _Select ANY that match this condition_
 - DropFunction() _Drop ANY that match this condition_

Filters are managed different for each Observation Point, however `drop` functions drop as soon as a match is found.

Select functions are active, meaning they will drop any data that does not match the select.

Consider the following stream of data where all integers 0 through 9 were sent through systems `select()` and `drop()`. 

```go
package main

func main() {
	data := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for _, n := range data {
		selectFunction(n)
		dropFunction(n)
    }
}
```

Select functions will return data that matches a condition (similar to [Unix](https://en.wikipedia.org/wiki/Filter_(software)#Unix)'s `grep` by Ken Thompson).

```go
package main 

func selectSeven(n int) bool {
    return n == 7
}
// output: _, _, _, _, _, _, _, 7, _, _,
```

Drop functions will drop data that matches a condition. 

```go
func dropSeven(n int) {
	return n != 7
}
// output: 0, 1, 2, 3, 4, 5, 6, _, 8, 9
```