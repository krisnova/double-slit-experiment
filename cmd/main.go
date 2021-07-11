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
	"os"

	userspace "github.com/kris-nova/double-slit-experiment/userspace/go"
	"github.com/kris-nova/logger"

	"github.com/urfave/cli/v2"
)

var (

	// [Command Line Flags]

	// rlimitinfinity toggles setrlimit()
	rlimitinfinity bool = true
)

func main() {

	app := &cli.App{
		Usage: "Container runtime telemetry",
		Name:  "The Double Slit Experiment",
		Action: func(context *cli.Context) error {
			cli.ShowAppHelpAndExit(context, 0)
			return nil
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "rlimit-infinity",
				Aliases:     []string{"r"},
				Value:       true,
				Destination: &rlimitinfinity,
				Usage:       "Toggle the kernel parameter setrlimit()",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "run",
				Aliases: []string{"a"},
				Usage:   "Run with the default profile, and print JSON events.",
				Action: func(c *cli.Context) error {
					return RunDSE() // X gonna give it to ya
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Critical(err.Error())
	}

}

func RunDSE() error {
	commandGlobalChecks()
	observer := userspace.NewObserver([]userspace.ObservationPoints{
		// TODO Pull these "profiles" out.
		userspace.ProcessExecuted,
	})
	observer.PrintJSONEvents()
	return nil
}

// commandGlobalChecks is used to check the runtime constraints of the
// system. This is just a collection of checks we use in many places.
func commandGlobalChecks() {
	// We will be loading eBPF probes directly into the kernel
	// at runtime, so we will need privileged access fundamentally.
	if !userspace.IsPrivileged() {
		logger.Critical("Permission denied.")
		os.Exit(-1)
	}

	if rlimitinfinity {
		err := userspace.SetRLimitInfinity()
		if err != nil {
			logger.Critical("Error setting rlimit: %v", err)
			os.Exit(1)
		}
	} else {
		// RLimit infinity should only be turned off in very rare situations (testing, debugging, etc)
		logger.Warning("setrlimit() infinity has NOT been enabled. errors may occur.")
	}
}
