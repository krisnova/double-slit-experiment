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

// #cgo CFLAGS: -g -Wall
// #include <linux/sched.h>
import "C"
import (
	"encoding/json"
	"fmt"

	"github.com/kris-nova/logger"

	"github.com/kris-nova/double-slit-experiment/system"

	"github.com/cilium/ebpf/perf"
)

type ContainerObservationPoint struct {
	reference            ObservationReference
	dropFunctions        []DropClone
	dropProcessFunctions []DropCloneProcess
}

func (c *ContainerObservationPoint) Event(record perf.Record) error {
	data, err := EventClone(record)
	if err != nil {
		return err
	}

	// Filter on the container fields
	for _, drop := range c.dropFunctions {
		if drop(data) {
			return nil
		}
	}

	// Deliberate design: We ignore errors if we can't lookup the process.
	// There is a non-zero chance the process has terminated.
	parentProc, err := system.ProcPIDLookup(int(data.Parent_tid))
	if err != nil {
		logger.Debug(err.Error())
	}
	childProc, err := system.ProcPIDLookup(int(data.Child_tid))
	if err != nil {
		logger.Debug(err.Error())
	}

	// Filter both processes
	for _, dropp := range c.dropProcessFunctions {
		if (childProc != nil && dropp(childProc)) || (parentProc != nil && dropp(parentProc)) {
			return nil
		}
	}

	//logger.Always("CloneEvent")
	c.reference.eventCh <- NewContainerEvent("Container", record.CPU, data, parentProc, childProc)
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

func NewContainerObservationPoint(dropFunctions []DropClone, dropProcessFunctions []DropCloneProcess) *ContainerObservationPoint {
	return &ContainerObservationPoint{
		dropFunctions:        dropFunctions,
		dropProcessFunctions: dropProcessFunctions,
	}
}

type ContainerEvent struct {
	CPU              int             `json:"CPU"`
	EventName        string          `json:"Name"`
	data             *clone_data_t   `json:"Data"`
	ParentPid        int             `json:"ParentPid"`
	ParentProc       *system.Process `json:"ParentProc"`
	ChildPid         int             `json:"ChildPid"`
	ChildProc        *system.Process `json:"ChildProc"`
	CloneFlags       uint            `json:"CloneFlags"`
	CloneFlagsByName []string        `json:"CloneFlagsByName"`
	TLS              uint            `json:"TLS"`
}

func NewContainerEvent(name string, cpu int, cloneData *clone_data_t, parentProc, childProc *system.Process) *ContainerEvent {
	return &ContainerEvent{
		CPU:              cpu,
		data:             cloneData,
		EventName:        name,
		ParentPid:        int(cloneData.Parent_tid),
		ParentProc:       parentProc,
		ChildPid:         int(cloneData.Child_tid),
		ChildProc:        childProc,
		CloneFlags:       uint(cloneData.Clone_flags),
		CloneFlagsByName: CloneFlagsByName(cloneData.Clone_flags),
		TLS:              uint(cloneData.TLS),
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

type DropCloneProcess func(p *system.Process) bool

func DropCloneExecutable(name string) DropCloneProcess {
	return func(p *system.Process) bool {
		return p.Executable == name
	}
}

const (
	CEMPTY               uint64 = 0x00000000             /* empty flag used for masking */
	CSIGNAL              uint64 = C.CSIGNAL              /* signal mask to be sent at exit */
	CLONE_VM             uint64 = C.CLONE_VM             /* set if VM shared between processes */
	CLONE_FS             uint64 = C.CLONE_FS             /* set if fs info shared between processes */
	CLONE_FILES          uint64 = C.CLONE_FILES          /* set if open files shared between processes */
	CLONE_SIGHAND        uint64 = C.CLONE_SIGHAND        /* set if signal handlers and blocked signals shared */
	CLONE_PIDFD          uint64 = C.CLONE_PIDFD          /* set if a pidfd should be placed in parent */
	CLONE_PTRACE         uint64 = C.CLONE_PTRACE         /* set if we want to let tracing continue on the child too */
	CLONE_VFORK          uint64 = C.CLONE_VFORK          /* set if the parent wants the child to wake it up on mm_release */
	CLONE_PARENT         uint64 = C.CLONE_PARENT         /* set if we want to have the same parent as the cloner */
	CLONE_THREAD         uint64 = C.CLONE_THREAD         /* Same thread group? */
	CLONE_NEWNS          uint64 = C.CLONE_NEWNS          /* New mount namespace group */
	CLONE_SYSVSEM        uint64 = C.CLONE_SYSVSEM        /* share system V SEM_UNDO semantics */
	CLONE_SETTLS         uint64 = C.CLONE_SETTLS         /* create a new TLS for the child */
	CLONE_PARENT_SETTID  uint64 = C.CLONE_PARENT_SETTID  /* set the TID in the parent */
	CLONE_CHILD_CLEARTID uint64 = C.CLONE_CHILD_CLEARTID /* clear the TID in the child */
	CLONE_DETACHED       uint64 = C.CLONE_DETACHED       /* Unused, ignored */
	CLONE_UNTRACED       uint64 = C.CLONE_UNTRACED       /* set if the tracing process can't force CLONE_PTRACE on this clone */
	CLONE_CHILD_SETTID   uint64 = C.CLONE_CHILD_SETTID   /* set the TID in the child */
	CLONE_NEWCGROUP      uint64 = C.CLONE_NEWCGROUP      /* New cgroup namespace */
	CLONE_NEWUTS         uint64 = C.CLONE_NEWUTS         /* New utsname namespace */
	CLONE_NEWIPC         uint64 = C.CLONE_NEWIPC         /* New ipc namespace */
	CLONE_NEWUSER        uint64 = C.CLONE_NEWUSER        /* New user namespace */
	CLONE_NEWPID         uint64 = C.CLONE_NEWPID         /* New pid namespace */
	CLONE_NEWNET         uint64 = C.CLONE_NEWNET         /* New network namespace */
	CLONE_IO             uint64 = C.CLONE_IO             /* Clone io context */
)

func CloneFlagsByName(flags uint64) []string {
	var nameFlags []string
	if flags&CSIGNAL == 0 {
		nameFlags = append(nameFlags, "CSIGNAL")
	}
	if flags&CLONE_VM == 0 {
		nameFlags = append(nameFlags, "CLONE_VM")
	}
	if flags&CLONE_FILES == 0 {
		nameFlags = append(nameFlags, "CLONE_FILES")
	}
	if flags&CLONE_SIGHAND == 0 {
		nameFlags = append(nameFlags, "CLONE_SIGHAND")
	}
	if flags&CLONE_PIDFD == 0 {
		nameFlags = append(nameFlags, "CLONE_PIDFD")
	}
	if flags&CLONE_PTRACE == 0 {
		nameFlags = append(nameFlags, "CLONE_PTRACE")
	}
	if flags&CLONE_VFORK == 0 {
		nameFlags = append(nameFlags, "CLONE_VFORK")
	}
	if flags&CLONE_PARENT == 0 {
		nameFlags = append(nameFlags, "CLONE_PARENT")
	}
	if flags&CLONE_THREAD == 0 {
		nameFlags = append(nameFlags, "CLONE_THREAD")
	}
	if flags&CLONE_NEWNS == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWNS")
	}
	if flags&CLONE_SYSVSEM == 0 {
		nameFlags = append(nameFlags, "CLONE_SYSVSEM")
	}
	if flags&CLONE_PIDFD == 0 {
		nameFlags = append(nameFlags, "CLONE_PIDFD")
	}
	if flags&CLONE_SETTLS == 0 {
		nameFlags = append(nameFlags, "CLONE_SETTLS")
	}
	if flags&CLONE_PARENT_SETTID == 0 {
		nameFlags = append(nameFlags, "CLONE_PARENT_SETTID")
	}
	if flags&CLONE_CHILD_CLEARTID == 0 {
		nameFlags = append(nameFlags, "CLONE_CLEARTID")
	}
	if flags&CLONE_DETACHED == 0 {
		nameFlags = append(nameFlags, "CLONE_DETACHED")
	}
	if flags&CLONE_UNTRACED == 0 {
		nameFlags = append(nameFlags, "CLONE_UNTRACED")
	}
	if flags&CLONE_CHILD_SETTID == 0 {
		nameFlags = append(nameFlags, "CLONE_CHILD_SETTID")
	}
	if flags&CLONE_NEWCGROUP == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWCGROUP")
	}
	if flags&CLONE_NEWUTS == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWUTS")
	}
	if flags&CLONE_NEWIPC == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWIPC")
	}
	if flags&CLONE_NEWUSER == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWUSER")
	}
	if flags&CLONE_NEWPID == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWPID")
	}
	if flags&CLONE_NEWNET == 0 {
		nameFlags = append(nameFlags, "CLONE_NEWNET")
	}
	//if flags&CLONE_TO == 0 {
	//	nameFlags = append(nameFlags, "CLONE_TO")
	//}
	return nameFlags
}

type DropClone func(d *clone_data_t) bool

func DropCloneChildEq0(d *clone_data_t) bool {
	return d.Child_tid == 0
}

func DropCloneFlagsEq0(d *clone_data_t) bool {
	return d.Clone_flags == 0
}

func DropCloneFlagMask(mask uint64) DropClone {
	return func(d *clone_data_t) bool {
		return d.Clone_flags&mask == 0
	}
}

func SelectCloneFlagMask(mask uint64) DropClone {
	return func(d *clone_data_t) bool {
		return d.Clone_flags&mask != 0
	}
}
