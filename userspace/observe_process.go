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

type ProcessObservationPoint struct {
	reference     ObservationReference
	execveFilters []FilterExecve
}

func (p *ProcessObservationPoint) Event(record perf.Record) error {
	data, err := EventExecve(record)
	if err != nil {
		return err
	}

	for _, filt := range p.execveFilters {
		if filt(data) {
			return nil
		}
	}

	//logger.Always("ProcessEvent")
	p.reference.eventCh <- NewProcessEvent("ProcessExecuted", record.CPU, data)
	return nil
}

func (p *ProcessObservationPoint) Tracepoints() map[string]TracepointData {
	return map[string]TracepointData{
		"sys_enter_execve": {
			Group:      BPFGroupSyscalls,
			Tracepoint: "sys_enter_execve",
			Program:    p.reference.probe.EnterExecve,
		},
	}
}

func (p *ProcessObservationPoint) SetReference(reference ObservationReference) {
	p.reference = reference
}

func NewProcessObservationPoint(execveFilters []FilterExecve) *ProcessObservationPoint {
	return &ProcessObservationPoint{
		execveFilters: execveFilters,
	}
}

type ProcessEvent struct {
	CPU       int            `json:"CPU"`
	EventName string         `json:"Name"`
	data      *execve_data_t `json:"Data"`
	Filename  string         `json:"Filename"`
	Comm      string         `json:"Comm"`
	PID       uint           `json:"PID"`
}

func NewProcessEvent(name string, cpu int, execData *execve_data_t) *ProcessEvent {
	return &ProcessEvent{
		data:      execData,
		CPU:       cpu,
		EventName: name,
		Filename:  BytesToString32(execData.Filename),
		Comm:      BytesToString32(execData.Comm),
		PID:       uint(execData.Pid),
	}
}

func (p *ProcessEvent) JSON() ([]byte, error) {
	return json.Marshal(p)
}

func (p *ProcessEvent) String() string {
	return fmt.Sprintf("[%s] (%d) (CPU: %d): %s", p.data.Comm, p.data.Pid, p.CPU, p.data.Filename)
}

func (p *ProcessEvent) Name() string {
	return p.EventName
}

type FilterExecve func(d *execve_data_t) bool

func FilterEmptyFilename(d *execve_data_t) bool {
	filename := BytesToString32(d.Filename)
	if filename == "" {
		return true
	}
	return false
}
