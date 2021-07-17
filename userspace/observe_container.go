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

	"github.com/cilium/ebpf/perf"
)

type ContainerObservationPoint struct {
	reference    ObservationReference
	cloneFilters []FilterClone
}

func (c *ContainerObservationPoint) Event(record perf.Record) error {
	data, err := EventClone(record)
	if err != nil {
		return err
	}

	for _, filt := range c.cloneFilters {
		if filt(data) {
			return nil
		}
	}

	//logger.Always("CloneEvent")
	c.reference.eventCh <- NewContainerEvent("ContainerStarted", record.CPU, data)
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

func NewContainerObservationPoint(cloneFilters []FilterClone) *ContainerObservationPoint {
	return &ContainerObservationPoint{
		cloneFilters: cloneFilters,
	}
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

type FilterClone func(d *clone_data_t) bool

func FilterChild0(d *clone_data_t) bool {
	if d.Child_tid == 0 {
		return true
	}
	return false
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

// FilterCloneFlagMask will default to an empty mask
//
var FilterCloneFlagMask uint64 = CEMPTY

// FilterCloneFlagsByMask will filter against
// whatever is defined in FilterCloneFlagMask
func FilterCloneFlagsByMask(d *clone_data_t) bool {
	if d.Clone_flags&FilterCloneFlagMask != 0 {
		return true
	}
	return false
}

// FilterCloneCSIGNAL         0x000000ff      /* signal mask to be sent at exit */
func FilterCloneCSIGNAL(d *clone_data_t) bool {
	var flag uint64
	flag = C.CSIGNAL
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_VM        0x00000100      /* set if VM shared between processes */
func FilterCloneCLONE_VM(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_VM
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_FS        0x00000200      /* set if fs info shared between processes */
func FilterCloneCLONE_FS(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_FS
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_FILES     0x00000400      /* set if open files shared between processes */
func FilterCloneCLONE_FILES(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_FILES
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_SIGHAND   0x00000800      /* set if signal handlers and blocked signals shared */
func FilterCloneCLONE_SIGHAND(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_SIGHAND
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_PIDFD     0x00001000      /* set if a pidfd should be placed in parent */
func FilterCloneCLONE_PIDFD(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_PIDFD
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_PTRACE    0x00002000      /* set if we want to let tracing continue on the child too */
func FilterCloneCLONE_PTRACE(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_PTRACE
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_VFORK     0x00004000      /* set if the parent wants the child to wake it up on mm_release */
func FilterCloneCLONE_VFORK(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_VFORK
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_PARENT    0x00008000      /* set if we want to have the same parent as the cloner */
func FilterCloneCLONE_PARENT(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_PARENT
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_THREAD    0x00010000      /* Same thread group? */
func FilterCloneCLONE_THREAD(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_THREAD
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWNS     0x00020000      /* New mount namespace group */
func FilterCloneCLONE_NEWNS(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWNS
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_SYSVSEM   0x00040000      /* share system V SEM_UNDO semantics */
func FilterCloneCLONE_SYSVSEM(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_SYSVSEM
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_SETTLS    0x00080000      /* create a new TLS for the child */
func FilterCloneCLONE_SETTLS(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_SETTLS
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_PARENT_SETTID     0x00100000      /* set the TID in the parent */
func FilterCloneCLONE_PARENT_SETTID(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_PARENT_SETTID
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_CHILD_CLEARTID    0x00200000      /* clear the TID in the child */
func FilterCloneCLONE_CHILD_CLEARTID(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_CHILD_CLEARTID
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_DETACHED          0x00400000      /* Unused, ignored */
func FilterCloneCLONE_DETACHED(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_DETACHED
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_UNTRACED          0x00800000      /* set if the tracing process can't force CLONE_PTRACE on this clone */
func FilterCloneCLONE_UNTRACED(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_UNTRACED
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_CHILD_SETTID      0x01000000      /* set the TID in the child */
func FilterCloneCLONE_CHILD_SETTID(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_CHILD_SETTID
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWCGROUP         0x02000000      /* New cgroup namespace */
func FilterCloneCLONE_NEWCGROUP(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWCGROUP
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWUTS            0x04000000      /* New utsname namespace */
func FilterCloneCLONE_NEWUTS(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWUTS
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWIPC            0x08000000      /* New ipc namespace */
func FilterCloneCLONE_NEWIPC(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWIPC
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWUSER           0x10000000      /* New user namespace */
func FilterCloneCLONE_NEWUSER(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWUSER
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWPID            0x20000000      /* New pid namespace */
func FilterCloneCLONE_NEWPID(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWPID
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

// FilterCloneCLONE_NEWNET            0x40000000      /* New network namespace */
func FilterCloneCLONE_NEWNET(d *clone_data_t) bool {
	var flag uint64
	flag = C.CLONE_NEWNET
	if d.Clone_flags&flag != 0 {
		return true
	}
	return false
}

///* Flags for the clone3() syscall. */
//#define CLONE_CLEAR_SIGHAND 0x100000000ULL /* Clear any signal handler and reset to SIG_DFL. */
//#define CLONE_INTO_CGROUP 0x200000000ULL /* Clone into a specific cgroup given the right permissions. */
