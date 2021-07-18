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
	"fmt"

	"github.com/cilium/ebpf/perf"
)

func EventSignal(event perf.Record) (*signal_data_t, error) {
	buffer := bytes.NewBuffer(event.RawSample)
	var data signal_data_t
	err := binary.Read(buffer, binary.LittleEndian, &data)
	if err != nil {
		return nil, fmt.Errorf("signal_delivered() kernel event perf: %v", err)
	}
	return &data, nil
}

type signal_data_t struct {
	Signal        int32
	Errno         int32
	Code          int32
	SignalHandler uint64
	SignalFlags   uint64
}
