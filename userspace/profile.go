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
		"SignalDelivered": NewSignalObservationPoint([]FilterSignal{}),
	}
}

func ProfileDefault() ObservationPoints {
	FilterCloneFlagMask = CEMPTY
	return ObservationPoints{
		"SocketState": NewSocketObservationPoint([]FilterSocket{
			FilterSocketProtocolNotZero,
		}),
		"SignalDelivered": NewSignalObservationPoint([]FilterSignal{
			FilterSignalCodeNotZero,
		}),
		"ProcessExecuted": NewProcessObservationPoint([]FilterExecve{
			FilterEmptyFilename,
		}),
		"ContainerStarted": NewContainerObservationPoint([]FilterClone{

			// Filter out all clone events where the child pid
			// is set to 0.
			FilterChild0,

			// Sometimes bash will fork, but use the clone()
			// syscall. We can filter those out now.
			FilterCloneCLONE_VFORK,

			//FilterCloneCLONE_NEWIPC,
			//FilterCloneCLONE_NEWCGROUP,
			//FilterCloneCLONE_NEWNET,
			//FilterCloneCLONE_NEWNS,
			//FilterCloneCLONE_NEWPID,
			//FilterCloneCLONE_NEWUSER,

			FilterCloneCLONE_VM,
			FilterCloneCLONE_FILES,
			FilterCloneCLONE_CHILD_CLEARTID,
			FilterCloneCLONE_PARENT,
			FilterCloneCLONE_PARENT_SETTID,
			FilterCloneCLONE_DETACHED,
			//FilterCloneCLONE_PTRACE,

			//FilterCloneFlagsByMask,
		}),
	}
}
