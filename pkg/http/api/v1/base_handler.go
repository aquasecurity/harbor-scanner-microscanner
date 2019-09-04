package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"net/http"
)

const (
	HeaderContentType = "Content-Type"
)

type BaseHandler struct {
}

func (h *BaseHandler) SendJSONError(w http.ResponseWriter, e harbor.Error) {
	data := struct {
		Err harbor.Error `json:"error"`
	}{e}
	b, err := json.Marshal(data)
	if err != nil {
		h.SendInternalServerError(w)
		return
	}
	w.Header().Set(HeaderContentType, "application/json")
	w.WriteHeader(e.HTTPCode)
	_, err = fmt.Fprintf(w, string(b))
	if err != nil {
		h.SendInternalServerError(w)
		return
	}
}

func (h *BaseHandler) SendInternalServerError(w http.ResponseWriter) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
