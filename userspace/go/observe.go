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
	"sync"

	"github.com/kris-nova/logger"
)

// ObservationPoints are small systems that are expected to "hang".
// These systems should return generic Event{}'s when an event occurs.
// These systems should error, and be restarted on error.
type ObservationPoints func(chan Event) error

// Observer is the main data structure that can be used
// to observe the system based on configured ObservationPoints.
type Observer struct {
	points  []ObservationPoints
	eventCh chan Event
}

// NewObserver is used to initialize and start a new
// observer. After calling this function, the observer
// will be listening to the kernel!
func NewObserver(points []ObservationPoints) *Observer {
	observer := &Observer{
		points:  points,
		eventCh: make(chan Event),
	}
	// Start the event stream on every New()!
	observer.start()
	return observer
}

// NextEvent will return the next Event in the "queue" otherwise block.
func (o *Observer) NextEvent() Event {
	return <-o.eventCh
}

// PrintJSONEvents will simply Print() the events in raw JSON
func (o *Observer) PrintJSONEvents() {
	for {
		event := <-o.eventCh
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
		event := <-o.eventCh
		logger.Info(event.String())
	}
}

// start is the main starting point of any configured Observer.
func (o *Observer) start() {
	once := sync.Once{}
	once.Do(func() {
		for _, obsPoint := range o.points {
			go func() {
				// Cycle the observation point
				// across all errors!
				for {
					err := obsPoint(o.eventCh)
					if err != nil {
						logger.Warning(err.Error())
					}
				}
			}()
		}
	})
}

// EventStream will return the channel of events.
// This is the same channel used in the other Observer methods.
func (o *Observer) EventStream() chan Event {
	return o.eventCh
}
