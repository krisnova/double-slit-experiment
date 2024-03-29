# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by executablelicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
#    ████╗  ██║██╔═████╗██║   ██║██╔══██╗
#    ██╔██╗ ██║██║██╔██║██║   ██║███████║
#    ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║
#    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
#    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝


executable=dse

.PHONY: build
build: clean gen $(executable)

.PHONY: run
run: build
	sudo ./$(executable)

.PHONY: gen
gen: sum vmlinux userspace/gen_probe_bpfel.go

.PHONY: vmlinux
vmlinux: probe/vmlinux.h

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt userspace/go/*.go

.PHONY: clean
clean:
	-rm $(executable)
	-rm userspace/gen*
	-rm probe/vmlinux.h

$(executable): cmd/main.go userspace/gen_probe_bpfel.go
	CGO_ENABLED=1 go build -o $(executable) cmd/main.go

probe/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > probe/vmlinux.h

userspace/gen_probe_bpfel.go: probe/bpf.c
	go generate userspace/*.go
	rm userspace/*.o

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix