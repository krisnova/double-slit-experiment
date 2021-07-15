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
	eventCh chan Event
}

// NewObserver is used to initialize and start a new
// observer. After calling this function, the observer
// will be listening to the kernel!
func NewObserver(points ObservationPoints) *Observer {
	observer := &Observer{
		points: points,
		reference: ObservationReference{
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

//func BPF_read_clone() (*perf.Reader, error) {
//	objs := gen_probeObjects{}
//	loadGen_probeObjects(&objs, nil)
//	link.Tracepoint("syscalls", "sys_enter_clone", objs.EnterClone)
//
//	if objs.Events == nil {
//		// We are unable to access events from the kernel, most likely
//		// this is a permissions error (not running as root/privileged).
//		return nil, fmt.Errorf("Unable to access events")
//	}
//
//	return perf.NewReader(objs.Events, os.Getpagesize())
//}

// Start is the main starting point of any configured Observer.
func (o *Observer) Start() error {
	probe := gen_probeObjects{}
	// ----------------------------------------------------------
	// [Load ObservationPoints]
	for name, obs := range o.points {
		logger.Debug("Loading ObservationPoint: %s", name)
		// Load the BPF components
		loadGen_probeObjects(&probe, nil)
		obs.LoadProbe(probe)
	}

	// ----------------------------------------------------------
	// [Load the global perf ring buffer]
	reader, err := perf.NewReader(probe.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("Unable to start perf reader: %v", err)
	}

	// ----------------------------------------------------------
	// [Start observing on each point]
	for name, obs := range o.points {
		logger.Debug("Observing ObservationPoint: %s", name)
		go func() {
			// Cycle the observation point
			// across all errors!
			for {
				// Holy shit! I did not realize you could
				// do this in Go!
				err := obs.ObservationFunc()(reader, o.reference)
				if err != nil {
					logger.Warning(err.Error())
				}
			}
		}()
	}
	// ----------------------------------------------------------
	return nil
}

// EventStream will return the channel of events.
// This is the same channel used in the other Observer methods.
func (o *Observer) EventStream() chan Event {
	return o.reference.eventCh
}

// ObservationPoint is the basic abstraction for all meaningful
// eBPF abstractions.
type ObservationPoint interface {

	// LoadProbe will pass in the BPF object program to load.
	LoadProbe(probe gen_probeObjects)

	// ObservationFunc is the main function that is executed for all ObservationPoints
	// I find it interesting how this model turned out very similar to HTTP APIs.
	ObservationFunc() func(reader *perf.Reader, reference ObservationReference) error
}

// ObservationPoints are small systems that are expected to "hang".
// These systems should return generic Event{}'s when an event occurs.
// These systems should error, and be restarted on error.
type ObservationPoints map[string]ObservationPoint
