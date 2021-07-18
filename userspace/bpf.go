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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang gen_probe ../probe/bpf.c ../probe/bpf.h -- -I/usr/include/bpf -I.

import (
	"fmt"
	"os"

	"inet.af/netaddr"

	"golang.org/x/sys/unix"
)

const (
	BPFGroupSyscalls = "syscalls"
	BPFGroupSignal   = "signal"
	BPFGroupSock     = "sock"
)

// IsPrivileged will check for UID 0
func IsPrivileged() bool {
	uid := os.Getuid()
	if uid != 0 {
		return false
	}
	return true
}

// SetRLimitInfinity will set the resource limit in the kernel
// to RLIM_INFINITY
// More:
//   https://linux.die.net/man/2/setrlimit
func SetRLimitInfinity() error {
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		})
	if err != nil {
		return fmt.Errorf("failed to set temporary rlimit: %v", err)
	}
	return nil
}

// BytesToString32 converts a [32]byte to a string
func BytesToString32(bytes [32]byte) string {
	var str string
	for _, b := range bytes {
		if b == 0 {
			continue
		}
		str = fmt.Sprintf("%s%s", str, string(b))
	}
	return str
}

func IPV4(bytes [4]byte) string {
	var ip string
	for _, oct := range bytes {
		oStr := fmt.Sprintf("%d", oct)
		if ip == "" {
			ip = oStr
		} else {
			ip = fmt.Sprintf("%s.%s", ip, oStr)
		}
	}
	return ip
}

func IPV6(bytes [16]byte) string {
	i := netaddr.IPv6Raw(bytes)
	return i.String()
}
