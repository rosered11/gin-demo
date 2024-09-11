package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// responseBodyWriter captures the response body for logging
type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseBodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b) // Capture the response body
	return w.ResponseWriter.Write(b)
}

func DefaultStructuredLogger() gin.HandlerFunc {
	return StructuredLogger(&log.Logger)
}

func StructuredLogger(logger *zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		var buf bytes.Buffer
		tee := io.TeeReader(c.Request.Body, &buf)
		reqBody, _ := io.ReadAll(tee)
		c.Request.Body = io.NopCloser(&buf)

		start := time.Now() // Start timer
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		traceID := c.Request.Header.Get("X-Trace-ID")
		if traceID == "" {
			traceID = generateTraceID() // Your custom function to generate a trace ID
		}

		// Capture the response body using a custom response writer
		resBodyWriter := &responseBodyWriter{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = resBodyWriter

		// Process request
		c.Next()

		// Fill the params
		param := gin.LogFormatterParams{}

		param.TimeStamp = time.Now() // Stop timer
		param.Latency = param.TimeStamp.Sub(start)
		if param.Latency > time.Minute {
			param.Latency = param.Latency.Truncate(time.Second)
		}

		param.ClientIP = c.ClientIP()
		param.Method = c.Request.Method
		param.StatusCode = c.Writer.Status()
		param.ErrorMessage = c.Errors.ByType(gin.ErrorTypePrivate).String()
		param.BodySize = c.Writer.Size()
		if raw != "" {
			path = path + "?" + raw
		}
		param.Path = path
		resBody := resBodyWriter.body.String()

		// Log using the params
		var logEvent *zerolog.Event
		if c.Writer.Status() >= 500 {
			logEvent = logger.Error()
		} else {
			logEvent = logger.Info()
		}

		logEvent.Str("trace_id", traceID).
			Str("client_id", param.ClientIP).
			Str("method", param.Method).
			Str("req_body", string(reqBody)).
			Int("status_code", param.StatusCode).
			Str("res_body", string(resBody)).
			Int("body_size", param.BodySize).
			Str("path", param.Path).
			Str("latency", param.Latency.String()).
			Msg(param.ErrorMessage)
	}
}

func generateTraceID() string {
	return uuid.NewString()
}
