package apierror

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ApiError struct {
	Message string `json:"message"`
}

func New(message string) ApiError {
	return ApiError{Message: message}
}

func AssertIsValid(t *testing.T, jsonData []byte) {
	apiError := ApiError{}
	err := json.Unmarshal(jsonData, &apiError)

	assert.Nil(t, err)
	assert.NotEmpty(t, apiError.Message)
}
