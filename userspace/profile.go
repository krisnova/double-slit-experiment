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

func ProfileSignalsOnly() ObservationPoints {
	return ObservationPoints{
		"SignalDelivered": NewSignalObservationPoint([]DropSignal{}),
	}
}

func ProfileDefault() ObservationPoints {
	return ObservationPoints{
		"SocketState": NewSocketObservationPoint([]DropSocket{

			// Drop all sockets where protocol = 0
			DropSocketProtocolEq0,
		}),
		"SignalDelivered": NewSignalObservationPoint([]DropSignal{

			// Drop all signals where flags = 0
			DropSignalFlagsEq0,

			// Drop all signals where code = 0
			DropSignalCodeEq0,
		}),
		"ProcessExecuted": NewProcessObservationPoint([]DropExecve{

			// Drop all execves with an empty filename
			DropExecveFilename(""),
		}),
		"ContainerStarted": NewContainerObservationPoint([]DropClone{
			// Drop all clones with these flags set
			DropCloneFlagMask(CLONE_VFORK),

			// Select clones with these flags set
			SelectCloneFlagMask(CLONE_PIDFD | CLONE_SYSVSEM),

			// Drop all clones where child PID = 0
			DropCloneChildEq0,

			// Drop all clones where flags = 0 (no arguments)
			DropCloneFlagsEq0,
		}, []DropCloneProcess{

			// Drop all clones that come from an executable named 'kthreadd'
			DropCloneExecutable("kthreadd"),
		}),
	}
}
