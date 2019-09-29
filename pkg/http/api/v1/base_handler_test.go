package v1

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBaseHandler_WriteJSONError(t *testing.T) {
	// given
	recorder := httptest.NewRecorder()
	handler := &BaseHandler{}

	// when
	handler.WriteJSONError(recorder, harbor.Error{
		HTTPCode: http.StatusBadRequest,
		Message:  "Invalid request",
	})

	// then
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.JSONEq(t, `{"error":{"message":"Invalid request"}}`, recorder.Body.String())
}
