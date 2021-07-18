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

func EventSock(event perf.Record) (*inet_sock_data_t, error) {
	buffer := bytes.NewBuffer(event.RawSample)
	var data inet_sock_data_t
	err := binary.Read(buffer, binary.LittleEndian, &data)
	if err != nil {
		return nil, fmt.Errorf("inet_sock kernel event perf: %v", err)
	}
	return &data, nil
}

type inet_sock_data_t struct {
	OldState int32
	NewState int32
	Sport    uint16
	Dport    uint16
	Family   uint16
	Protocol uint16
	Saddr    [4]byte
	Daddr    [4]byte
	Saddr_v6 [16]byte
	Daddr_v6 [16]byte
}
