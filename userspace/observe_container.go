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

type ContainerObservationPoint struct {
	reference ObservationReference
}

func (c *ContainerObservationPoint) Event(record perf.Record) error {
	cloneData, err := EventClone(record)
	if err != nil {
		return err
	}

	// Filter childpid=0
	if cloneData.Child_tid == 0 {
		return nil
	}

	//logger.Always("CloneEvent")
	c.reference.eventCh <- NewContainerEvent("ContainerStarted", record.CPU, cloneData)
	return nil
}

func (c *ContainerObservationPoint) Tracepoints() map[string]TracepointData {
	return map[string]TracepointData{
		"sys_enter_clone": {
			Group:      BPFGroupSyscalls,
			Tracepoint: "sys_enter_clone",
			Program:    c.reference.probe.EnterExecve,
		},
	}
}

func (c *ContainerObservationPoint) SetReference(reference ObservationReference) {
	c.reference = reference
}

func NewContainerObservationPoint() *ContainerObservationPoint {
	return &ContainerObservationPoint{}
}

type ContainerEvent struct {
	CPU        int           `json:"CPU"`
	EventName  string        `json:"Name"`
	data       *clone_data_t `json:"Data"`
	ParentPid  int           `json:"ParentPid"`
	ChildPid   int           `json:"ChildPid"`
	CloneFlags uint          `json:"CloneFlags"`
}

func NewContainerEvent(name string, cpu int, cloneData *clone_data_t) *ContainerEvent {
	return &ContainerEvent{
		CPU:        cpu,
		data:       cloneData,
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
	return fmt.Sprintf("[CPU %d] Parent(%d) -> Child(%d) [%d]", e.CPU, e.data.Parent_tid, e.data.Child_tid, e.data.Clone_flags)
}

func (e *ContainerEvent) Name() string {
	return e.EventName
}
