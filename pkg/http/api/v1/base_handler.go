package v1

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	log "github.com/sirupsen/logrus"
	"net/http"
)

const (
	HeaderContentType = "Content-Type"
)

type BaseHandler struct {
}

func (h *BaseHandler) WriteJSON(res http.ResponseWriter, data interface{}, mimeType string, statusCode int) {
	res.Header().Set(HeaderContentType, mimeType)
	res.WriteHeader(statusCode)

	err := json.NewEncoder(res).Encode(data)
	if err != nil {
		log.WithError(err).Error("Error while writing JSON")
		h.SendInternalServerError(res)
	}
}

func (h *BaseHandler) WriteJSONError(res http.ResponseWriter, e harbor.Error) {
	data := struct {
		Err harbor.Error `json:"error"`
	}{e}
	h.WriteJSON(res, data, "application/vnd.scanner.adapter.error", e.HTTPCode)
}

func (h *BaseHandler) SendInternalServerError(w http.ResponseWriter) {
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
