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
	reference ObservationReference
}

func (p *ProcessObservationPoint) Event(record perf.Record) error {
	execData, err := EventExecve(record)
	if err != nil {
		return err
	}

	// Filter filename=""
	fileName := BytesToString32(execData.F_name)
	if fileName == "" {
		return nil
	}

	//logger.Always("ProcessEvent")
	p.reference.eventCh <- NewProcessEvent("ProcessExecuted", record.CPU, execData)
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

func NewProcessObservationPoint() *ProcessObservationPoint {
	return &ProcessObservationPoint{}
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
		EventName: name,
		Filename:  BytesToString32(execData.F_name),
		Comm:      BytesToString32(execData.Comm),
		PID:       uint(execData.Pid),
	}
}

func (p *ProcessEvent) JSON() ([]byte, error) {
	return json.Marshal(p)
}

func (p *ProcessEvent) String() string {
	return fmt.Sprintf("[%s] (%d) (CPU: %d): %s", p.data.Comm, p.data.Pid, p.CPU, p.data.F_name)
}

func (p *ProcessEvent) Name() string {
	return p.EventName
}
