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
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func BPF_read_clone() (*perf.Reader, error) {
	objs := gen_probeObjects{}
	loadGen_probeObjects(&objs, nil)
	link.Tracepoint("syscalls", "sys_enter_clone", objs.EnterClone)

	if objs.Events == nil {
		// We are unable to access events from the kernel, most likely
		// this is a permissions error (not running as root/privileged).
		return nil, fmt.Errorf("Unable to access events")
	}

	return perf.NewReader(objs.Events, os.Getpagesize())
}

type clone_data_t struct {
	Parent_tid  int
	Child_tid   int
	Clone_flags uint64
}
