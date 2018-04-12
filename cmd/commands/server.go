// Copyright (c) 2016-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package commands

import (
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	l4g "github.com/alecthomas/log4go"
	"github.com/WTHealth/server/api"
	"github.com/WTHealth/server/app"
	"github.com/WTHealth/server/cmd"
	"github.com/WTHealth/server/model"
	"github.com/WTHealth/server/utils"
	"github.com/spf13/cobra"
)

const (
	SESSIONS_CLEANUP_BATCH_SIZE = 1000
)

var serverCmd = &cobra.Command{
	Use:          "server",
	Short:        "Run the Mattermost server",
	RunE:         serverCmdF,
	SilenceUsage: true,
}

func init() {
	cmd.RootCmd.AddCommand(serverCmd)
	cmd.RootCmd.RunE = serverCmdF
}

func serverCmdF(command *cobra.Command, args []string) error {
	config, err := command.Flags().GetString("config")
	if err != nil {
		return err
	}

	interruptChan := make(chan os.Signal, 1)
	return runServer(config, interruptChan)
}

func runServer(configFileLocation string, interruptChan chan os.Signal) error {
	options := []app.Option{app.ConfigFile(configFileLocation)}

	a, err := app.New(options...)
	if err != nil {
		l4g.Critical(err.Error())
		return err
	}
	defer a.Shutdown()

	pwd, _ := os.Getwd()
	l4g.Info("mattermost.working_dir", pwd)
	l4g.Info("mattermost.config_file", utils.FindConfigFile(configFileLocation))

	serverErr := a.StartServer()
	if serverErr != nil {
		l4g.Critical(serverErr.Error())
		return serverErr
	}

	api.Init(a, a.Srv.Router)

	a.ReloadConfig()

	a.Go(func() {
		runSessionCleanupJob(a)
	})
	a.Go(func() {
		runTokenCleanupJob(a)
	})

	notifyReady()

	// wait for kill signal before attempting to gracefully shutdown
	// the running service
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-interruptChan

	return nil
}


func runTokenCleanupJob(a *app.App) {
	doTokenCleanup(a)
	model.CreateRecurringTask("Token Cleanup", func() {
		doTokenCleanup(a)
	}, time.Hour*1)
}

func runSessionCleanupJob(a *app.App) {
	doSessionCleanup(a)
	model.CreateRecurringTask("Session Cleanup", func() {
		doSessionCleanup(a)
	}, time.Hour*24)
}

func notifyReady() {
	// If the environment vars provide a systemd notification socket,
	// notify systemd that the server is ready.
	systemdSocket := os.Getenv("NOTIFY_SOCKET")
	if systemdSocket != "" {
		l4g.Info("Sending systemd READY notification.")

		err := sendSystemdReadyNotification(systemdSocket)
		if err != nil {
			l4g.Error(err.Error())
		}
	}
}

func sendSystemdReadyNotification(socketPath string) error {
	msg := "READY=1"
	addr := &net.UnixAddr{
		Name: socketPath,
		Net:  "unixgram",
	}
	conn, err := net.DialUnix(addr.Net, nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}

func doTokenCleanup(a *app.App) {
	a.Srv.Store.Token().Cleanup()
}

func doSessionCleanup(a *app.App) {
	a.Srv.Store.Session().Cleanup(model.GetMillis(), SESSIONS_CLEANUP_BATCH_SIZE)
}
