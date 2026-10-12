package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type helperRequest struct {
	Action string `json:"action"`
}

type helperResponse struct {
	OK                bool                     `json:"ok"`
	Status            string                   `json:"status"`
	TunEnabled        bool                     `json:"tun_enabled,omitempty"`
	TunTestConfirmed  bool                     `json:"tun_test_confirmed,omitempty"`
	Supported         bool                     `json:"supported,omitempty"`
	Stacks            []string                 `json:"stacks,omitempty"`
	ApplicationUpdate *applicationUpdateStatus `json:"application_update,omitempty"`
}

var fixedHelperActions = map[string]struct{}{
	"mihomo-update-prepare": {},
	"mihomo-update-install": {}, "mihomo-update-rollback": {},
	"app-update-start": {}, "app-update-status": {},
	"mihomo-start": {}, "mihomo-stop": {}, "mihomo-restart": {},
	"tun-enable": {}, "tun-disable": {}, "tun-status": {}, "tun-diagnostics": {},
	"network-prepare": {}, "network-confirm": {}, "network-abort": {}, "network-rollback": {},
}

func dispatchHelperAction(action string) helperResponse {
	if _, ok := fixedHelperActions[action]; !ok {
		return helperResponse{Status: "unsupported action"}
	}
	return helperResponse{OK: true, Status: "accepted"}
}

func decodeHelperRequest(r io.Reader) (string, error) {
	data, err := bufio.NewReader(io.LimitReader(r, 4097)).ReadBytes('\n')
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", errors.New("request is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request helperRequest
	if err := decoder.Decode(&request); err != nil {
		return "", err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", errors.New("request must contain one JSON object")
	}
	if _, ok := fixedHelperActions[request.Action]; !ok {
		return "", errors.New("unsupported action")
	}
	return request.Action, nil
}

func handleHelperProtocol(r io.Reader, w io.Writer) error {
	action, err := decodeHelperRequest(r)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(dispatchHelperAction(action))
}
