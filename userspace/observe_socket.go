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

type SocketObservationPoint struct {
	reference     ObservationReference
	socketFilters []FilterSocket
}

func (p *SocketObservationPoint) Event(record perf.Record) error {
	data, err := EventSock(record)
	if err != nil {
		return err
	}

	for _, filt := range p.socketFilters {
		if filt(data) {
			return nil
		}
	}

	p.reference.eventCh <- NewSocketEvent("SocketState", record.CPU, data)
	return nil
}

func (p *SocketObservationPoint) Tracepoints() map[string]TracepointData {
	return map[string]TracepointData{
		"inet_sock": {
			Group:      BPFGroupSock,
			Tracepoint: "inet_sock_set_state",
			Program:    p.reference.probe.InetSockSetState,
		},
	}
}

func (p *SocketObservationPoint) SetReference(reference ObservationReference) {
	p.reference = reference
}

func NewSocketObservationPoint(socketFilters []FilterSocket) *SocketObservationPoint {
	return &SocketObservationPoint{
		socketFilters: socketFilters,
	}
}

type SocketEvent struct {
	CPU          int               `json:"CPU"`
	EventName    string            `json:"Name"`
	data         *inet_sock_data_t `json:"Data"`
	OldState     int               `json:"OldState"`
	NewState     int               `json:"NewState"`
	SourcePort   uint              `json:"SourcePort"`
	DestPort     uint              `json:"DestPort"`
	Family       uint              `json:"Family"`
	Protocol     uint              `json:"Protocol"`
	SourceAddr   string            `json:"SourceAddr"`
	DestAddr     string            `json:"DestAddr"`
	SourceAddrV6 string            `json:"SourceAddrV6"`
	DestAddrV6   string            `json:"DestAddrV6"`
}

func NewSocketEvent(name string, cpu int, data *inet_sock_data_t) *SocketEvent {
	return &SocketEvent{
		data:         data,
		EventName:    name,
		CPU:          cpu,
		OldState:     int(data.OldState),
		NewState:     int(data.NewState),
		SourcePort:   uint(data.Sport),
		DestPort:     uint(data.Dport),
		Family:       uint(data.Family),
		Protocol:     uint(data.Protocol),
		SourceAddr:   IPV4(data.Saddr),
		DestAddr:     IPV4(data.Daddr),
		SourceAddrV6: IPV6(data.Saddr_v6),
		DestAddrV6:   IPV6(data.Daddr_v6),
	}
}

func (p *SocketEvent) JSON() ([]byte, error) {
	return json.Marshal(p)
}

func (p *SocketEvent) String() string {
	return fmt.Sprintf("")
}

func (p *SocketEvent) Name() string {
	return p.EventName
}

type FilterSocket func(d *inet_sock_data_t) bool

func FilterSocketProtocolNotZero(d *inet_sock_data_t) bool {
	if d.Protocol != 0 {
		return true
	}
	return false
}
