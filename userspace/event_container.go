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

func ContainerStarted(ch chan Event) error {
	reader, err := BPF_read_clone()
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
		var data clone_data_t
		err = binary.Read(b, binary.LittleEndian, &data)
		if err != nil {
			return fmt.Errorf("Kernel perf event error: %v", err)
		}

		// Send Event over channel
		p := NewContainerEvent(event, data, "ContainerStarted", 110)
		ch <- p
	}
	return nil
}

type ContainerEvent struct {
	Event      perf.Record  `json:"Event"`
	EventCode  int          `json:"Code,omitempty"`
	EventName  string       `json:"Name"`
	data       clone_data_t `json:"Data"`
	ParentPid  int          `json:"ParentPid"`
	ChildPid   int          `json:"ChildPid"`
	CloneFlags uint         `json: "CloneFlags"`
}

func NewContainerEvent(event perf.Record, cloneData clone_data_t, name string, code int) *ContainerEvent {
	return &ContainerEvent{
		Event:      event,
		data:       cloneData,
		EventCode:  code,
		EventName:  name,
		ParentPid:  int(cloneData.Parent_tid),
		ChildPid:   int(cloneData.Child_tid),
		CloneFlags: uint(cloneData.Clone_flags),
	}
}

func (e *ContainerEvent) JSON() ([]byte, error) {
	return json.Marshal(e)
}

func (e *ContainerEvent) String() string {
	return fmt.Sprintf("Parent(%d) -> Child(%d) [%d]", e.data.Parent_tid, e.data.Child_tid, e.data.Clone_flags)
}

func (e *ContainerEvent) Code() int {
	return e.EventCode
}

func (e *ContainerEvent) Name() string {
	return e.EventName
}
