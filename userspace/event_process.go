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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf/perf"
)

func ProcessExecuted(ch chan Event) error {
	reader, err := BPF_read_execve()
	if err != nil {
		return err
	}
	for {
		event, err := reader.Read()
		if err != nil {
			return fmt.Errorf("Read event error: %v", err)
		}

		if event.LostSamples != 0 {
			return fmt.Errorf("Kernel event ring buffer full, dropped %d events", event.LostSamples)
		}

		b := bytes.NewBuffer(event.RawSample)
		var data exec_data_t
		err = binary.Read(b, binary.LittleEndian, &data)
		if err != nil {
			return fmt.Errorf("Kernel perf event error: %v", err)
		}

		// Send Event over channel
		p := NewProcessEvent(event, data, "ProcessExecuted", 100)
		ch <- p
	}
	return nil
}

type ProcessEvent struct {
	Event     perf.Record `json:"Event"`
	EventCode int         `json:"Code,omitempty"`
	EventName string      `json:"Name"`
	data      exec_data_t `json:"Data"`
	Filename  string      `json:"Filename"`
	Comm      string      `json:"Comm"`
	PID       uint        `json: "PID"`
}

func NewProcessEvent(event perf.Record, execData exec_data_t, name string, code int) *ProcessEvent {
	return &ProcessEvent{
		Event:     event,
		data:      execData,
		EventCode: code,
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
	return fmt.Sprintf("[%s] (%d) (CPU: %d): %s", p.data.Comm, p.data.Pid, p.Event.CPU, p.data.F_name)
}

func (p *ProcessEvent) Code() int {
	return p.EventCode
}

func (p *ProcessEvent) Name() string {
	return p.EventName
}
