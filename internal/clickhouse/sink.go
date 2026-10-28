// Package clickhouse ships usage records and captured request bodies to
// ClickHouse over its HTTP interface. Writes are asynchronous, batched and
// bounded: proxied requests are never blocked or failed by the sink.
package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

const (
	defaultEndpoint          = "http://127.0.0.1:8123"
	defaultDatabase          = "cliproxy"
	defaultUsername          = "default"
	defaultPasswordEnv       = "CLICKHOUSE_PASSWORD"
	defaultMaxBodyBytes      = 1 << 20
	defaultBodyRetentionDays = 30
	defaultBatchSize         = 200
	defaultFlushInterval     = 2 * time.Second
	defaultQueueSize         = 10000

	// The sink talks to a local observability database, not an upstream
	// provider, so a request timeout keeps a stalled server from wedging the worker.
	httpTimeout         = 30 * time.Second
	schemaRetryInterval = 30 * time.Second
	dropReportInterval  = time.Minute
	// maxQueuedBytes bounds memory held by buffered rows (mostly bodies), in
	// addition to the row-count bound from queue-size.
	maxQueuedBytes  = 256 << 20
	maxErrorSnippet = 512
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Settings is the resolved sink configuration.
type Settings struct {
	Enabled           bool
	Endpoint          string
	Database          string
	Username          string
	Password          string
	CaptureBodies     bool
	MaxBodyBytes      int
	BodyRetentionDays int
	BatchSize         int
	FlushInterval     time.Duration
	QueueSize         int
}

// SettingsFromConfig resolves defaults and reads the password from the configured
// environment variable.
func SettingsFromConfig(cfg *config.Config) Settings {
	if cfg == nil {
		return Settings{}
	}
	raw := cfg.ClickHouse
	s := Settings{
		Enabled:           raw.Enabled,
		Endpoint:          strings.TrimRight(strings.TrimSpace(raw.Endpoint), "/"),
		Database:          strings.TrimSpace(raw.Database),
		Username:          strings.TrimSpace(raw.Username),
		CaptureBodies:     raw.CaptureBodies,
		MaxBodyBytes:      raw.MaxBodyBytes,
		BodyRetentionDays: raw.BodyRetentionDays,
		BatchSize:         raw.BatchSize,
		QueueSize:         raw.QueueSize,
	}
	if s.Endpoint == "" {
		s.Endpoint = defaultEndpoint
	}
	if s.Database == "" {
		s.Database = defaultDatabase
	}
	if s.Username == "" {
		s.Username = defaultUsername
	}
	passwordEnv := strings.TrimSpace(raw.PasswordEnv)
	if passwordEnv == "" {
		passwordEnv = defaultPasswordEnv
	}
	s.Password = os.Getenv(passwordEnv)
	if s.MaxBodyBytes <= 0 {
		s.MaxBodyBytes = defaultMaxBodyBytes
	}
	if s.BodyRetentionDays <= 0 {
		s.BodyRetentionDays = defaultBodyRetentionDays
	}
	if s.BatchSize <= 0 {
		s.BatchSize = defaultBatchSize
	}
	if s.QueueSize <= 0 {
		s.QueueSize = defaultQueueSize
	}
	s.FlushInterval = defaultFlushInterval
	if d, err := time.ParseDuration(strings.TrimSpace(raw.FlushInterval)); err == nil && d > 0 {
		s.FlushInterval = d
	}
	return s
}

// Validate reports configuration errors that would make every write fail.
func (s Settings) Validate() error {
	if !identifierPattern.MatchString(s.Database) {
		return fmt.Errorf("clickhouse: invalid database name %q", s.Database)
	}
	parsed, err := url.Parse(s.Endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("clickhouse: invalid endpoint %q", s.Endpoint)
	}
	return nil
}

type queuedRow struct {
	table string
	row   any
	size  int64
}

// Sink buffers rows and writes them to ClickHouse in batches.
type Sink struct {
	settings Settings
	client   *http.Client
	queue    chan queuedRow
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	stopped  atomic.Bool

	queuedBytes atomic.Int64
	dropped     atomic.Uint64
	failed      atomic.Uint64
	written     atomic.Uint64
	schemaReady bool
	lastSchema  time.Time
}

// NewSink creates a sink and starts its worker goroutine.
func NewSink(settings Settings, client *http.Client) *Sink {
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	s := &Sink{
		settings: settings,
		client:   client,
		queue:    make(chan queuedRow, settings.QueueSize),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go s.run()
	return s
}

// Settings returns the sink configuration.
func (s *Sink) Settings() Settings {
	if s == nil {
		return Settings{}
	}
	return s.settings
}

// Enqueue adds a row without blocking. It returns false and counts a drop when
// the queue is full or the sink is stopped.
func (s *Sink) Enqueue(table string, row any) bool {
	return s.EnqueueSized(table, row, 0)
}

// EnqueueSized is Enqueue for rows with a known approximate size in bytes; rows
// are also dropped when buffered rows would exceed maxQueuedBytes.
func (s *Sink) EnqueueSized(table string, row any, size int64) bool {
	if s == nil {
		return false
	}
	if s.stopped.Load() {
		s.dropped.Add(1)
		return false
	}
	if size > 0 && s.queuedBytes.Add(size) > maxQueuedBytes {
		s.queuedBytes.Add(-size)
		s.dropped.Add(1)
		return false
	}
	select {
	case s.queue <- queuedRow{table: table, row: row, size: size}:
		return true
	default:
		s.queuedBytes.Add(-size)
		s.dropped.Add(1)
		return false
	}
}

// Dropped returns the number of rows dropped because the queue was full.
func (s *Sink) Dropped() uint64 { return s.dropped.Load() }

// Failed returns the number of rows lost to failed inserts.
func (s *Sink) Failed() uint64 { return s.failed.Load() }

// Written returns the number of rows successfully inserted.
func (s *Sink) Written() uint64 { return s.written.Load() }

// Close stops the worker after flushing queued rows, waiting until ctx expires.
func (s *Sink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		s.stopped.Store(true)
		close(s.stop)
	})
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sink) run() {
	defer close(s.done)
	s.ensureSchema()

	ticker := time.NewTicker(s.settings.FlushInterval)
	defer ticker.Stop()
	reportTicker := time.NewTicker(dropReportInterval)
	defer reportTicker.Stop()

	batches := map[string][]any{}
	batchBytes := map[string]int64{}
	flushTable := func(table string) {
		if len(batches[table]) > 0 {
			s.flush(table, batches[table])
		}
		s.queuedBytes.Add(-batchBytes[table])
		batches[table] = nil
		batchBytes[table] = 0
	}
	add := func(item queuedRow) {
		batches[item.table] = append(batches[item.table], item.row)
		batchBytes[item.table] += item.size
		if len(batches[item.table]) >= s.settings.BatchSize {
			flushTable(item.table)
		}
	}
	flushAll := func() {
		for table := range batches {
			flushTable(table)
		}
	}
	var reportedDropped, reportedFailed uint64

	for {
		select {
		case item := <-s.queue:
			add(item)
		case <-ticker.C:
			flushAll()
		case <-reportTicker.C:
			dropped, failed := s.dropped.Load(), s.failed.Load()
			if dropped != reportedDropped || failed != reportedFailed {
				log.Warnf("clickhouse sink: %d rows dropped (queue full), %d rows lost to failed inserts since start", dropped, failed)
				reportedDropped, reportedFailed = dropped, failed
			}
		case <-s.stop:
		drain:
			for {
				select {
				case item := <-s.queue:
					add(item)
				default:
					break drain
				}
			}
			flushAll()
			if dropped, failed := s.dropped.Load(), s.failed.Load(); dropped > 0 || failed > 0 {
				log.Warnf("clickhouse sink stopped: %d rows dropped (queue full), %d rows lost to failed inserts", dropped, failed)
			}
			return
		}
	}
}

func (s *Sink) flush(table string, rows []any) {
	if len(rows) == 0 {
		return
	}
	if !s.schemaReady && time.Since(s.lastSchema) >= schemaRetryInterval {
		s.ensureSchema()
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, row := range rows {
		if errEncode := encoder.Encode(row); errEncode != nil {
			log.WithError(errEncode).Warn("clickhouse sink: failed to encode row")
		}
	}
	query := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", quoteIdent(s.settings.Database), quoteIdent(table))
	if errExec := s.exec(context.Background(), query, &body); errExec != nil {
		s.failed.Add(uint64(len(rows)))
		log.WithError(errExec).Warnf("clickhouse sink: failed to insert %d rows into %s", len(rows), table)
		return
	}
	s.written.Add(uint64(len(rows)))
}

// ensureSchema creates the database and tables when missing. It is idempotent.
func (s *Sink) ensureSchema() {
	s.lastSchema = time.Now()
	ctx := context.Background()
	for _, statement := range schemaStatements(s.settings) {
		if errExec := s.exec(ctx, statement, nil); errExec != nil {
			log.WithError(errExec).Warn("clickhouse sink: schema setup failed; will retry")
			return
		}
	}
	if errTTL := s.syncBodiesTTL(ctx); errTTL != nil {
		log.WithError(errTTL).Warn("clickhouse sink: failed to update bodies TTL")
	}
	s.schemaReady = true
}

// syncBodiesTTL updates the bodies table TTL when body-retention-days changed.
func (s *Sink) syncBodiesTTL(ctx context.Context) error {
	query := fmt.Sprintf("SELECT engine_full FROM system.tables WHERE database = '%s' AND name = '%s' FORMAT TabSeparatedRaw", s.settings.Database, tableBodies)
	var out bytes.Buffer
	if errExec := s.execOutput(ctx, query, nil, &out); errExec != nil {
		return errExec
	}
	if strings.Contains(out.String(), fmt.Sprintf("toIntervalDay(%d)", s.settings.BodyRetentionDays)) {
		return nil
	}
	return s.exec(ctx, fmt.Sprintf("ALTER TABLE %s.%s MODIFY TTL %s", quoteIdent(s.settings.Database), quoteIdent(tableBodies), bodiesTTL(s.settings.BodyRetentionDays)), nil)
}

func (s *Sink) exec(ctx context.Context, query string, body io.Reader) error {
	return s.execOutput(ctx, query, body, io.Discard)
}

func (s *Sink) execOutput(ctx context.Context, query string, body io.Reader, out io.Writer) error {
	endpoint := s.settings.Endpoint + "/?query=" + url.QueryEscape(query)
	if body == nil {
		body = http.NoBody
	}
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if errReq != nil {
		return errReq
	}
	req.Header.Set("X-ClickHouse-User", s.settings.Username)
	if s.settings.Password != "" {
		req.Header.Set("X-ClickHouse-Key", s.settings.Password)
	}
	resp, errDo := s.client.Do(req)
	if errDo != nil {
		return errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Debug("clickhouse sink: failed to close response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorSnippet))
		return fmt.Errorf("clickhouse returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, errCopy := io.Copy(out, resp.Body)
	return errCopy
}

func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "") + "`"
}

func bodiesTTL(days int) string {
	return fmt.Sprintf("toDateTime(requested_at) + toIntervalDay(%d)", days)
}

func schemaStatements(s Settings) []string {
	db := quoteIdent(s.Database)
	return []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", db),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s (
    requested_at DateTime64(3, 'UTC'),
    request_id String,
    execution_id String,
    selection_id String,
    provider LowCardinality(String),
    executor_type LowCardinality(String),
    base_url String,
    model LowCardinality(String),
    alias String,
    response_model String,
    auth_id String,
    auth_index String,
    auth_type LowCardinality(String),
    source String,
    access_provider LowCardinality(String),
    client_key_id LowCardinality(String),
    is_native_key UInt8,
    session_id String,
    parent_session_id String,
    stream UInt8,
    generate UInt8,
    reasoning_effort LowCardinality(String),
    service_tier LowCardinality(String),
    effective_service_tier LowCardinality(String),
    response_service_tier LowCardinality(String),
    latency_ms Int64,
    ttft_ms Int64,
    failed UInt8,
    status_code UInt16,
    error_code LowCardinality(String),
    error_body String,
    input_tokens Int64,
    output_tokens Int64,
    reasoning_tokens Int64,
    cached_tokens Int64,
    cache_read_tokens Int64,
    cache_creation_tokens Int64,
    total_tokens Int64,
    response_headers Map(String, String)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(requested_at)
ORDER BY (provider, model, requested_at)`, db, quoteIdent(tableUsage)),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s (
    requested_at DateTime64(3, 'UTC'),
    request_id String,
    url String,
    method LowCardinality(String),
    status_code UInt16,
    duration_ms Int64,
    client_key_id LowCardinality(String),
    request_headers Map(String, String),
    response_headers Map(String, String),
    request_body String CODEC(ZSTD(3)),
    request_body_bytes Int64,
    request_body_truncated UInt8,
    upstream_request String CODEC(ZSTD(3)),
    upstream_request_bytes Int64,
    upstream_request_truncated UInt8,
    upstream_response String CODEC(ZSTD(3)),
    upstream_response_bytes Int64,
    upstream_response_truncated UInt8,
    response_body String CODEC(ZSTD(3)),
    response_body_bytes Int64,
    response_body_truncated UInt8,
    INDEX idx_request_id request_id TYPE bloom_filter GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toYYYYMM(requested_at)
ORDER BY (requested_at, request_id)
TTL %s`, db, quoteIdent(tableBodies), bodiesTTL(s.BodyRetentionDays)),
	}
}
