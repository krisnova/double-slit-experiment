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

package system

import (
	"os"
	"sync"

	"github.com/mitchellh/go-ps"
)

type Process struct {
	Executable string
	ParentPid  int
	Pid        int
	mtx        sync.Mutex
	*os.Process
}

// ProcPIDLookup will look in userspace memory
// and in the /proc filesystem for process meta.
//
// TODO: We should consider completely removing the concept of "/proc" from this work (just because we can).
func ProcPIDLookup(pid int) (*Process, error) {
	p := &Process{}

	// Lookup the "Go" concept of a process
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	// Lookup the "Linux" concept of a process
	// /proc/$pid/stat
	// TODO: Let's just read from /proc ourselves (we are missing data).
	procp, err := ps.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	if procp == nil {
		return nil, nil
	}
	p.Executable = procp.Executable()
	p.ParentPid = procp.PPid()
	p.Pid = procp.Pid()
	p.Process = proc
	return p, nil
}
