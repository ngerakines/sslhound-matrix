package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/matrix-org/gomatrix"
	"github.com/ngerakines/sslhound-matrix/check"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"
)

type Matrix struct {
	AccessToken string `json:"access_token"`
	UserID      string `json:"user_id"`
	HomeServer  string `json:"home_server"`
}

type handler struct {
	Client *gomatrix.Client
}

func (h *handler) handleMessage(event *gomatrix.Event) {
	body := event.Content["body"].(string)
	log.Println(body)

	messageParts := strings.Split(body, " ")
	if len(messageParts) != 2 {
		return
	}

	if messageParts[0] != "!check" {
		return
	}

	_, err := h.Client.SendText(event.RoomID, fmt.Sprintf("Checking %s ...", messageParts[1]))
	if err != nil {
		log.Println("Unable to send checking message:", err)
		return
	}

	host, port, err := net.SplitHostPort(messageParts[1])
	if err != nil {
		log.Println("Invalid target:", err)
		return
	}

	collector := make(chan check.CollectedInfo, 100)

	opts := []check.Option{
		check.WithContext(context.Background()),
		check.CollectTiming(),
	}

	err = check.RunCheck(collector, host, port, opts...)
	if err != nil {
		log.Println("Error running check:", err)
	}

	message := "ok"
	if err != nil {
		message = "error"
	}

	close(collector)

	details := make([]string, 0)
	for ci := range collector {
		log.Println("collected info", ci.Name, ci.Value, ci.Duration)
		parts := []string{ci.Name}
		if len(ci.Value) > 0 {
			parts = append(parts, ci.Value)
		}
		if ci.Duration > 0 {
			parts = append(parts, ci.Duration.String())
		}
		details = append(details, strings.Join(parts, ":"))
	}

	if err != nil {
		details = append([]string{err.Error()}, details...)
	}

	out := fmt.Sprintf("<strong>%s</strong>", message)
	out += "<ul>"
	for _, detail := range details {
		out += fmt.Sprintf("<li>%s</li>", detail)
	}
	out += "</ul>"


	_, err = h.Client.SendFormattedText(event.RoomID, message + " " + strings.Join(details, ";"), out)
	if err != nil {
		log.Println("Unable to send checking message:", err)
		return
	}
}

func (h *handler) handleMembership(event *gomatrix.Event) {
	if membership, ok := event.Content["membership"]; !ok || membership != "invite" {
		return
	}


	log.Println("Trying to join room: ", event.RoomID)

	time.Sleep(1 * time.Second)
	_, err := h.Client.JoinRoom(event.RoomID, "", struct{}{})
	if err != nil {
		log.Println("unable to join room:", err)
	}

	log.Println("joined room:", event.RoomID)

	_, err = h.Client.SendText(event.RoomID, "sslhound reporting for duty")
	if err != nil {
		log.Println("unable to send welcome message:", err)
	}
}

func main() {
	var configPathFlag string

	flag.StringVar(&configPathFlag, "config", "config.json", "Configuration file to load")

	flag.Parse() // NewFlagSet(os.Args[0], ExitOnError)

	configBytes, err := ioutil.ReadFile(configPathFlag)
	if err != nil {
		log.Fatal(err)
	}

	matrixConfig := &Matrix{}
	if err := json.Unmarshal(configBytes, matrixConfig); err != nil {
		log.Fatal(err)
	}

	matrixClient, err := gomatrix.NewClient(matrixConfig.HomeServer, matrixConfig.UserID, matrixConfig.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	botHandler := &handler{
		Client: matrixClient,
	}

	syncer := matrixClient.Syncer.(*gomatrix.DefaultSyncer)

	syncer.OnEventType("m.room.message", botHandler.handleMessage)
	syncer.OnEventType("m.room.member", botHandler.handleMembership)

	log.Println("Syncing")
	if err := botHandler.Client.Sync(); err != nil {
		log.Fatal(err)
	}

}
