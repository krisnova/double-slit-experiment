//
// Copyright © 2021 Kris Nóva <kris@nivenly.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
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

package main

import (
	"encoding/binary"
	"bytes"
	"os"
	"github.com/kris-nova/logger"
	userspace "github.com/kris-nova/double-slit-experiment/userspace/go"
)

func main() {

	err := userspace.SetRLimitInfinity()
	if err != nil {
		logger.Critical("Error setting rlimit: %v", err)
		os.Exit(1)
	}

	reader, err := userspace.ExecveR()
	if err != nil {
		logger.Critical("Error: %v", err)
		os.Exit(1)
	}

	// Sample code for now
	// Do not keep!
	// We can use this to understand how
	// we can start pulling data out of
	// the kernel.
	for {
		event, err := reader.Read()
		if err != nil {
			logger.Warning("Read event error: %v", err)
		}

		if event.LostSamples != 0 {
			logger.Warning("Kernel event ring buffer full, dropped %d events", event.LostSamples)
			continue
		}

		b := bytes.NewBuffer(event.RawSample)

		var data userspace.E_exec_data_t
		err = binary.Read(b, binary.LittleEndian, &data)
		if err != nil {
			logger.Warning("Kernel perf event error: %v", err)
			continue
		}

		// event (CPU info)
		// data
		logger.Always("[%s] (%d): %s", data.Comm, data.Pid, data.F_name)
	}

}