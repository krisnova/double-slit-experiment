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
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf/perf"
)

type SignalObservationPoint struct {
	reference     ObservationReference
	signalFilters []FilterSignal
}

func (p *SignalObservationPoint) Event(record perf.Record) error {
	data, err := EventSignal(record)
	if err != nil {
		return err
	}

	for _, filt := range p.signalFilters {
		if filt(data) {
			return nil
		}
	}

	//logger.Always("ProcessEvent")
	p.reference.eventCh <- NewSignalEvent("SignalDelivered", record.CPU, data)
	return nil
}

func (p *SignalObservationPoint) Tracepoints() map[string]TracepointData {
	return map[string]TracepointData{
		"signal_deliver": {
			Group:      BPFGroupSignal,
			Tracepoint: "signal_deliver",
			Program:    p.reference.probe.SignalDeliver,
		},
	}
}

func (p *SignalObservationPoint) SetReference(reference ObservationReference) {
	p.reference = reference
}

func NewSignalObservationPoint(signalFilters []FilterSignal) *SignalObservationPoint {
	return &SignalObservationPoint{
		signalFilters: signalFilters,
	}
}

type SignalEvent struct {
	CPU       int            `json:"CPU"`
	EventName string         `json:"Name"`
	data      *signal_data_t `json:"Data"`
	Signal    int            `json:"Signal"`
	Errno     int            `json:"Errno"`
	Code      int            `json:"Code"`
	Handler   uint64         `json:"Handler"`
	Flags     uint64         `json:"Flag"`
}

func NewSignalEvent(name string, cpu int, signalData *signal_data_t) *SignalEvent {
	return &SignalEvent{
		data:      signalData,
		EventName: name,
		Signal:    signalData.Signal,
		Errno:     signalData.Errno,
		Code:      signalData.Code,
		Handler:   signalData.SA_Handler,
		Flags:     signalData.SA_Flags,
	}
}

func (p *SignalEvent) JSON() ([]byte, error) {
	return json.Marshal(p)
}

func (p *SignalEvent) String() string {
	return fmt.Sprintf("")
}

func (p *SignalEvent) Name() string {
	return p.EventName
}

type FilterSignal func(d *signal_data_t) bool
