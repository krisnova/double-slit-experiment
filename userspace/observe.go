// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
//    ████╗  ██║██╔═████╗██║   ██║██╔══██╗
//    ██╔██╗ ██║██║██╔██║██║   ██║███████║
//    ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║
//    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
//    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝

package userspace

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/perf"

	"github.com/kris-nova/logger"
)

// Observer is the main data structure that can be used
// to observe the system based on configured ObservationPoints.
type Observer struct {
	points    ObservationPoints
	reference ObservationReference
}

// ObservationReference will set the reference for
// various ObservationPoints with the BPF libraries.
type ObservationReference struct {
	probe   gen_probeObjects
	eventCh chan Event
}

// NewObserver is used to initialize and start a new
// observer. After calling this function, the observer
// will be listening to the kernel!
func NewObserver(points ObservationPoints) *Observer {
	probe := gen_probeObjects{}
	loadGen_probeObjects(&probe, nil)
	observer := &Observer{
		points: points,
		reference: ObservationReference{
			probe:   probe,
			eventCh: make(chan Event),
		},
	}
	return observer
}

// NextEvent will return the next Event in the "queue" otherwise block.
func (o *Observer) NextEvent() Event {
	return <-o.reference.eventCh
}

// PrintJSONEvents will simply Print() the events in raw JSON
func (o *Observer) PrintJSONEvents() {
	for {
		event := <-o.reference.eventCh
		b, err := event.JSON()
		if err != nil {
			fmt.Printf("{\"Error\": \"%v\"}\n", err)
			continue
		}
		fmt.Println(string(b))
	}
}

// LogEvents is used to log the event.String() using the configured
// logger.
func (o *Observer) LogEvents() {
	for {
		event := <-o.reference.eventCh
		logger.Info(event.String())
	}
}

// Start is the main starting point of any configured Observer.
func (o *Observer) Start() error {
	// [Load Tracepoints]
	for _, obs := range o.points {
		obs.SetReference(o.reference)
		for _, td := range obs.Tracepoints() {
			logger.Info("Loading tracepoint: %s/%s", td.Group, td.Tracepoint)
			_, err := link.Tracepoint(td.Group, td.Tracepoint, td.Program)
			if err != nil {
				return fmt.Errorf("Error loading tracepoint: %v", err)
			}
		}
	}

	// [Load the global perf ring buffer]
	logger.Info("Loading BPF Probe")
	reader, err := perf.NewReader(o.reference.probe.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("Unable to start perf reader: %v", err)
	}

	// [ Main Processor ]
	go func() {
		for {
			event, err := reader.Read()
			if err != nil {
				logger.Warning(err.Error())
			}
			if event.LostSamples > 0 {
				logger.Warning("Dropping kernel samples: %d", event.LostSamples)
				continue
			}
			for _, point := range o.points {
				go func() {
					err := point.Event(event)
					if err != nil {
						// TODO Handle error
						//logger.Warning(err.Error())
					}
				}()
			}
		}
	}()
	return nil
}

// EventStream will return the channel of events.
// This is the same channel used in the other Observer methods.
func (o *Observer) EventStream() chan Event {
	return o.reference.eventCh
}

type TracepointData struct {
	Group      string
	Tracepoint string
	Program    *ebpf.Program
}

// ObservationPoint is the basic abstraction for all meaningful
// eBPF abstractions.
// Examples:
//    - ContainerStarted
//    - ProcessExecuted
type ObservationPoint interface {
	Tracepoints() map[string]TracepointData
	Event(record perf.Record) error
	SetReference(reference ObservationReference)
}

// ObservationPoints are small systems that are expected to "hang".
// These systems should return generic Event{}'s when an event occurs.
// These systems should error, and be restarted on error.
type ObservationPoints map[string]ObservationPoint
