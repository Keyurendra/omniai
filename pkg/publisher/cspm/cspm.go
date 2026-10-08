package cspm

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/avast/retry-go/v4"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/scanner"
)

type Config struct {
	Endpoint            string
	TenantID            uint
	LabelID             string
	Token               string
	SkipTLSVerification bool
}

func (c Config) Validate() error {
	if c.TenantID == 0 {
		return fmt.Errorf("missing `TenantID`")
	}
	if c.LabelID == "" {
		return fmt.Errorf("missing `LabelID`")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("missing `Endpoint`")
	}
	if !c.isValidEndpoint() {
		return fmt.Errorf("invalid `Endpoint`")
	}
	if c.Token == "" {
		return fmt.Errorf("missing `Token`")
	}
	if !c.isValidJWT() {
		return fmt.Errorf("invalid `Token`")
	}
	return nil
}

func (c Config) isValidEndpoint() bool {
	parsed, err := url.ParseRequestURI(c.Endpoint)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	// reject non-ASCII or space characters in host
	if strings.ContainsAny(parsed.Host, " \t\n\r") {
		return false
	}
	return true
}

func (c Config) isValidJWT() bool {
	parts := strings.Split(c.Token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts[:2] {
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return false
		}
	}
	return true
}

// contextWriter wraps an io.Writer and checks context cancellation
type contextWriter struct {
	w   io.Writer
	ctx context.Context
}

func (cw *contextWriter) Write(p []byte) (n int, err error) {
	select {
	case <-cw.ctx.Done():
		return 0, cw.ctx.Err()
	default:
		return cw.w.Write(p)
	}
}

type Publisher struct {
	c      Config
	logger *slog.Logger
}

func NewPublisher(c Config, l *slog.Logger) (publisher.Publisher, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validating provided config: %w", err)
	}
	if l == nil {
		l = slog.Default().With("publisher", `cspm`)
	}
	return &Publisher{c: c, logger: l}, nil
}

func (p Publisher) Publish(ctx context.Context, findings ...scanner.Findings) error {
	for _, f := range findings {
		err := p.uploadFinding(ctx, f)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p Publisher) buildArtifactURL(dataType string) (*url.URL, error) {
	u, err := url.Parse(p.c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint %q: %w", p.c.Endpoint, err)
	}

	q := u.Query()
	q.Set("tenant_id", strconv.FormatUint(uint64(p.c.TenantID), 10))
	q.Set("label_id", p.c.LabelID)
	q.Set("save_to_s3", "true")
	q.Set("data_type", dataType)
	u.RawQuery = q.Encode()

	return u, nil
}

func (p Publisher) uploadFinding(ctx context.Context, f scanner.Findings) error {
	dataType := f.DataType()
	if dataType == "AIAGENT" {
		dataType = "TR"
	}

	url, err := p.buildArtifactURL(dataType)
	if err != nil {
		return fmt.Errorf("building artifact URL: %w", err)
	}

	retryOpts := []retry.Option{
		retry.Context(ctx),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(attempt uint, err error) {
			p.logger.LogAttrs(
				ctx,
				slog.LevelError,
				fmt.Sprintf("publish retry attempt %d", attempt),
				slog.Any("error", err),
			)
		}),
	}

	return retry.Do(func() error {
		var wg sync.WaitGroup
		defer wg.Wait()

		attemptCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		contentType := mw.FormDataContentType()

		wg.Go(func() {
			defer pw.Close()
			defer mw.Close()

			part, err := mw.CreateFormFile("file", "artifact.json")
			if err != nil {
				p.logger.LogAttrs(
					ctx,
					slog.LevelError,
					"failed to create multipart form file",
					slog.String("error", err.Error()),
				)
				err := fmt.Errorf("creating form file: %w", err)
				pw.CloseWithError(err)
				return
			}

			ctxWriter := &contextWriter{
				w:   part,
				ctx: attemptCtx,
			}

			enc := jsontext.NewEncoder(ctxWriter)
			if err := json.MarshalEncode(enc, f); err != nil {
				p.logger.LogAttrs(
					ctx,
					slog.LevelError,
					"failed to encode findings into json",
					slog.String("data_type", f.DataType()),
					slog.String("error", err.Error()),
				)
				pw.CloseWithError(fmt.Errorf("encoding %q findings: %w", f.DataType(), err))
				return
			}
		})

		req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, url.String(), pr)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+p.c.Token)
		req.Header.Set("Content-Type", contentType)

		client := http.DefaultClient
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: p.c.SkipTLSVerification,
		}
		client.Transport = transport

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("http request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}

		return fmt.Errorf("%s: %s", resp.Status, string(body))
	}, retryOpts...)
}
