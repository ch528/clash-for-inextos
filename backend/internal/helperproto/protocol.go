package helperproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const MaxRequestSize = 4096

type Request struct {
	Action string `json:"action"`
}

type Response struct {
	OK         bool   `json:"ok"`
	Status     string `json:"status"`
	PID        int    `json:"pid,omitempty"`
	TunEnabled bool   `json:"tun_enabled,omitempty"`
	Interface  string `json:"interface,omitempty"`
}

var allowedActions = map[string]struct{}{
	"mihomo-start": {}, "mihomo-stop": {}, "mihomo-restart": {}, "mihomo-status": {},
	"tun-enable": {}, "tun-disable": {}, "tun-status": {}, "tun-diagnostics": {},
	"network-rollback": {}, "network-confirm": {}, "network-status": {},
	"apply-transparent-proxy": {},
}

func DecodeRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestSize+1))
	if err != nil {
		return Request{}, err
	}
	if len(data) > MaxRequestSize {
		return Request{}, errors.New("request is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("request must contain one JSON object")
	}
	if _, ok := allowedActions[request.Action]; !ok {
		return Request{}, errors.New("unsupported action")
	}
	return request, nil
}
