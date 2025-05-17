# VictoriaMetrics Enhancement Proposals(VEPs): Automation Kubernetes Monitoring for vmagent

**Status**: Proposed  
**Version**: v1  
**Last Updated**: 2025-03-17

## Table of Contents

- [VictoriaMetrics Enhancement Proposals(VEPs): Automation Kubernetes Monitoring for vmagent](#victoriametrics-enhancement-proposalsveps-automation-kubernetes-monitoring-for-vmagent)
	- [Table of Contents](#table-of-contents)
	- [Overview](#overview)
	- [Motivation](#motivation)
	- [Goals](#goals)
	- [Non-Goals](#non-goals)
	- [Proposal](#proposal)
		- [Architecture Design](#architecture-design)
		- [Command Line Parameters Design](#command-line-parameters-design)
		- [Built-in Collectors Design](#built-in-collectors-design)
			- [1. Node Metrics Collector](#1-node-metrics-collector)
			- [2. Container Metrics Collector](#2-container-metrics-collector)
			- [3. Kubernetes State Metrics Collector](#3-kubernetes-state-metrics-collector)
			- [4. Application Auto-Discovery](#4-application-auto-discovery)
		- [Implementation](#implementation)
			- [Collector Interface](#collector-interface)
			- [vmagent Main Configuration](#vmagent-main-configuration)
			- [Node Collector Implementation](#node-collector-implementation)
			- [Kubernetes API Client](#kubernetes-api-client)
	- [Risks and Mitigations](#risks-and-mitigations)
	- [Implementation Progress](#implementation-progress)
	- [Test Plan](#test-plan)
		- [Prerequisite testing updates](#prerequisite-testing-updates)
		- [Unit tests](#unit-tests)
		- [Integration tests](#integration-tests)
		- [e2e tests](#e2e-tests)
	- [Graduation Criteria](#graduation-criteria)
		- [Alpha](#alpha)
		- [Beta](#beta)
		- [Stable](#stable)
	- [Deprecated](#deprecated)
	- [Disabled](#disabled)
	- [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
		- [Upgrade Strategy](#upgrade-strategy)
		- [Downgrade Strategy](#downgrade-strategy)
		- [Version Skew Strategy](#version-skew-strategy)
	- [Production Readiness Review Questionnaire](#production-readiness-review-questionnaire)
		- [Feature Enablement and Rollback](#feature-enablement-and-rollback)
		- [Rollout, Upgrade and Rollback Planning](#rollout-upgrade-and-rollback-planning)
		- [Monitoring Requirements](#monitoring-requirements)
		- [Dependencies](#dependencies)
		- [Scalability](#scalability)
		- [Troubleshooting](#troubleshooting)
	- [Implementation History](#implementation-history)
	- [Drawbacks](#drawbacks)
	- [Alternatives](#alternatives)
	- [References](#references)

## Overview

This proposal aims to simplify Kubernetes monitoring configuration by integrating lightweight monitoring components into vmagent, replacing complex YAML configurations with a single command-line flag. This approach enables vmagent to automatically discover and collect key metrics from Kubernetes clusters without deploying multiple standalone components, significantly reducing configuration complexity and resource consumption.

## Motivation

According to the issues described in [GitHub issue #1393](https://github.com/VictoriaMetrics/VictoriaMetrics/issues/1393), current Kubernetes monitoring faces several key challenges:

1. **Complex Configuration**:
   - Kubernetes service discovery (kubernetes_sd_config) configuration is extremely complex
   - Typical configurations include hundreds of lines of difficult-to-understand YAML
   - Different configurations produce different metric names and labels, making it difficult to create unified dashboards and alerting rules
   - DevOps professionals often can only copy configuration snippets from the internet without understanding how the entire system works

2. **Multiple Component Dependencies**:
   - Requires separate deployment of kube-state-metrics
   - Requires cadvisor on each node
   - Requires node-exporter on each node
   - Requires configuration for application metrics scraping

3. **Resource Waste**: 
   - Many generated metrics are never used in dashboards or alerting rules but still consume storage resources
   - Multiple components increase overall resource consumption

4. **Operational Complexity**: 
   - Operators like Prometheus Operator or VictoriaMetrics Operator generate huge scrape configs with unreadable relabeling rules
   - Difficult to understand, configure, and debug the monitoring setup

By providing a single vmagent deployment with built-in lightweight collectors and simple command-line parameters to enable standardized Kubernetes monitoring, we can greatly simplify this process while ensuring consistent metric naming and labeling conventions.

## Goals

1. Provide a simple command-line flag `-promscrape.kubernetes=true` to enable Kubernetes monitoring
2. Deploy vmagent as a DaemonSet with minimal configuration to monitor all Kubernetes components
3. Integrate lightweight alternatives to eliminate dependencies on node-exporter, cadvisor, and kube-state-metrics
4. Ensure exact compatibility with metric names and labels from standard components for dashboard/alerting compatibility
5. Simplify automatic discovery and collection of application metrics through annotations
6. Collect only essential metrics that are actually used in dashboards and alerting rules
7. Provide official Kubernetes monitoring dashboards and alerting rules

## Non-Goals

1. Completely replicate all metrics from traditional components
2. Support all possible Kubernetes monitoring scenarios and configuration options
3. Replace advanced custom monitoring requirements

## Proposal

### Architecture Design

vmagent will be deployed as a DaemonSet on each node in the Kubernetes cluster, integrating the following functionalities directly within the vmagent binary:

1. **Node Metrics Collector**: A lightweight Go package that replaces node-exporter, exposing only the essential node-level metrics frequently used in dashboards and alerting rules.

2. **Container Metrics Collector**: A lightweight Go package that replaces cadvisor, collecting only the essential container-level metrics frequently used in dashboards and alerting rules.

3. **Kubernetes State Metrics Collector**: A lightweight Go package that replaces kube-state-metrics, exposing only the essential Kubernetes object states frequently used in dashboards and alerting rules.

4. **Application Auto-Discovery**: Automatically discovers and scrapes application metrics based on annotations such as `victoriametrics.com/scrape`, `victoriametrics.com/port`, and `victoriametrics.com/path`.

Key design principles:
- **Metric Compatibility**: Collected metrics names and labels are exactly the same as node-exporter, cadvisor, and kube-state-metrics, ensuring compatibility with existing dashboards, alerts, and recording rules
- **Lightweight Implementation**: Avoid using over-engineered official packages, use simpler alternatives like `github.com/VictoriaMetrics/metrics` or direct `fmt.Fprintf` for metrics exposition
- **Avoid Kubernetes SDK**: Use VictoriaMetrics' existing Kubernetes discovery code or lightweight HTTP client instead of the official Kubernetes SDK to reduce binary size
- **Simplified Architecture**: Minimize configuration complexity, focus on core functionality with the smallest possible set of metrics
- **Efficient Resource Usage**: Start with the minimal set of essential metrics and add others based on user demand

### Command Line Parameters Design

Following the principle of keeping the architecture as simple as possible, we will start with only a minimal set of command-line parameters necessary for basic functionality:

```bash
# Core switch
-promscrape.kubernetes=true                          # Main switch: Enable Kubernetes monitoring functionality

# Collector selection
-promscrape.kubernetes.collectors=node,container,kube-state,app  # Specify enabled collectors (comma-separated)

# Global collection interval
-promscrape.kubernetes.interval="15s"                # Default collection interval for all collectors

# Namespaces filter (optional)
-promscrape.kubernetes.namespaces=""                 # Limit to specific namespaces (comma-separated, empty means all)
-promscrape.kubernetes.exclude-namespaces=""         # Exclude specific namespaces (comma-separated)
```

This minimal approach provides:
1. A single flag to enable/disable the entire functionality
2. A simple way to select which collectors to enable
3. A global collection interval that applies to all collectors
4. Basic namespace filtering when needed

Additional parameters will only be added based on real user demand and if they align with the project's vision of simplicity and efficiency.

### Built-in Collectors Design

#### 1. Node Metrics Collector

A lightweight node-exporter alternative that collects key node metrics:

- CPU usage
- Memory usage
- Filesystem space
- Network throughput
- System load

Key metrics examples (compatible with node-exporter):
```
node_cpu_seconds_total{cpu="0", mode="user"} 24.5
node_memory_MemTotal_bytes 16106127360
node_memory_MemFree_bytes 8053063680
node_filesystem_avail_bytes{device="/dev/sda1", mountpoint="/", fstype="ext4"} 52034642240
node_network_receive_bytes_total{device="eth0"} 1234567890
node_load1 0.42
```

#### 2. Container Metrics Collector

An efficient cadvisor alternative that collects container resource usage metrics:

- Container CPU usage and limits
- Container memory usage and limits
- Container network usage
- Container disk I/O

Key metrics examples (compatible with cadvisor):
```
container_cpu_usage_seconds_total{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default"} 15.7
container_memory_usage_bytes{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default"} 67108864
container_memory_working_set_bytes{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default"} 58982400
container_cpu_cfs_throttled_seconds_total{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default"} 0.45
```

#### 3. Kubernetes State Metrics Collector

An efficient kube-state-metrics alternative that collects Kubernetes object states:

- Pod status and counts
- Deployment status and replica counts
- Node status and conditions
- Service and endpoint information

Key metrics examples (compatible with kube-state-metrics):
```
kube_pod_status_phase{namespace="default", pod="web-1", phase="Running"} 1
kube_deployment_status_replicas{namespace="default", deployment="web"} 3
kube_deployment_status_replicas_available{namespace="default", deployment="web"} 3
kube_deployment_status_replicas_ready{namespace="default", deployment="web"} 3
kube_node_status_condition{node="worker-1", condition="Ready", status="true"} 1
```

#### 4. Application Auto-Discovery

Auto-discovers and scrapes application metrics based on annotations:

- Uses `victoriametrics.com/scrape: "true"` annotation to mark scrapable Pods
- Configures scrape details through `victoriametrics.com/path`, `victoriametrics.com/port`, `victoriametrics.com/scheme` annotations
- Supports role-based service discovery: pod, service, node, endpoints, ingress

### Implementation

The implementation will focus on creating lightweight, efficient collectors that can be embedded directly in vmagent without external dependencies.

#### Collector Interface

```go
// pkg/kubernetes/collector/collector.go

package collector

import (
	"context"
	"io"
	"time"
)

// Collector defines the interface that all Kubernetes metric collectors must implement
type Collector interface {
	// Name returns the unique name of the collector
	Name() string

	// Description returns the description of the collector
	Description() string

	// Initialize initializes the collector
	Initialize() error

	// Start starts the collector's run loop, returning a Stop function
	Start(ctx context.Context) (StopFunc, error)

	// WriteMetrics writes collected metrics to the provided io.Writer in Prometheus text format
	WriteMetrics(w io.Writer) error
}

// StopFunc is used to stop the collector
type StopFunc func()

// Config represents the minimal configuration options for a collector
type Config struct {
	// Interval represents the collection interval
	Interval time.Duration

	// Namespaces represents the namespaces to monitor (empty means all)
	Namespaces []string

	// ExcludeNamespaces represents the namespaces to exclude
	ExcludeNamespaces []string
}
```

#### vmagent Main Configuration

```go
// cmd/vmagent/main.go

package main

import (
	"flag"
	"log"

	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/kubernetes"
)

var (
	// Kubernetes monitoring related flags
	kubernetesEnabled = flag.Bool("promscrape.kubernetes", false, 
		"Whether to enable built-in Kubernetes monitoring (node, container, kube-state metrics)")
	
	kubernetesInterval = flag.Duration("promscrape.kubernetes.interval", 15*time.Second, 
		"Collection interval for Kubernetes metrics")
	
	kubernetesNamespaces = flag.String("promscrape.kubernetes.namespaces", "", 
		"Comma-separated list of namespaces to monitor; leave empty to monitor all namespaces")
	
	kubernetesExcludeNamespaces = flag.String("promscrape.kubernetes.exclude-namespaces", "", 
		"Comma-separated list of namespaces to exclude from monitoring")
)

func main() {
	// Parse command line arguments
	flag.Parse()

	// Other vmagent initialization code...

	// If Kubernetes monitoring is enabled, initialize the Kubernetes monitoring module
	if *kubernetesEnabled {
		log.Printf("Enabling built-in Kubernetes monitoring")
		
		// Create Kubernetes monitoring manager
		k8sMgr, err := kubernetes.NewManager(*kubernetesInterval, 
			parseNamespaces(*kubernetesNamespaces), 
			parseNamespaces(*kubernetesExcludeNamespaces))
		if err != nil {
			log.Fatalf("Unable to initialize Kubernetes monitoring: %s", err)
		}
		
		// Start Kubernetes monitoring
		if err := k8sMgr.Start(); err != nil {
			log.Fatalf("Unable to start Kubernetes monitoring: %s", err)
		}
		
		// Stop Kubernetes monitoring when the program exits
		defer k8sMgr.Stop()
	}

	// Other vmagent code...
}

// parseNamespaces parses comma-separated namespaces into a slice
func parseNamespaces(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
```

#### Node Collector Implementation

```go
// pkg/kubernetes/node/collector.go

package node

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
	
	// Use direct system call packages rather than wrappers where possible
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	
	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/kubernetes/collector"
)

// Collector implements node metrics collection
type Collector struct {
	// Context and lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	interval   time.Duration
	
	// Mutexes for thread safety
	mu         sync.Mutex
}

// NewCollector creates a new node collector
func NewCollector(config collector.Config) (*Collector, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Collector{
		ctx:        ctx,
		cancel:     cancel,
		interval:   config.Interval,
	}, nil
}

// Name returns the collector name
func (c *Collector) Name() string {
	return "node-collector"
}

// Description returns the collector description
func (c *Collector) Description() string {
	return "Collects essential node-level system metrics, replacing node-exporter"
}

// Initialize initializes the collector
func (c *Collector) Initialize() error {
	return nil
}

// Start begins the metrics collection loop
func (c *Collector) Start(ctx context.Context) (collector.StopFunc, error) {
	c.ctx = ctx
	
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				// No need to do anything here, metrics are collected on-demand when WriteMetrics is called
			case <-c.ctx.Done():
				return
			}
		}
	}()
	
	return func() {
		c.cancel()
		c.wg.Wait()
	}, nil
}

// WriteMetrics writes collected metrics to io.Writer
func (c *Collector) WriteMetrics(w io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Collect CPU metrics
	cpuTimes, err := cpu.Times(true)
	if err != nil {
		return fmt.Errorf("unable to get CPU times: %w", err)
	}
	
	for _, ct := range cpuTimes {
		fmt.Fprintf(w, "node_cpu_seconds_total{cpu=\"%s\",mode=\"user\"} %.2f\n", ct.CPU, ct.User)
		fmt.Fprintf(w, "node_cpu_seconds_total{cpu=\"%s\",mode=\"system\"} %.2f\n", ct.CPU, ct.System)
		fmt.Fprintf(w, "node_cpu_seconds_total{cpu=\"%s\",mode=\"idle\"} %.2f\n", ct.CPU, ct.Idle)
		// Only add the most important CPU modes
	}
	
	// Collect memory metrics
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return fmt.Errorf("unable to get memory info: %w", err)
	}
	
	fmt.Fprintf(w, "node_memory_MemTotal_bytes %d\n", memInfo.Total)
	fmt.Fprintf(w, "node_memory_MemFree_bytes %d\n", memInfo.Free)
	fmt.Fprintf(w, "node_memory_MemAvailable_bytes %d\n", memInfo.Available)
	// Only add the most important memory metrics

	// Filesystem metrics would be added here, but only essential ones
	
	// Network metrics would be added here, but only essential ones
	
	// Load metrics would be added here, but only essential ones
	
	return nil
}
```

#### Kubernetes API Client

```go
// pkg/kubernetes/client/client.go

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client is a lightweight Kubernetes API client
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	caCert     []byte
}

// NewClient creates a new Kubernetes API client.
// It automatically detects in-cluster configuration when baseURL and token are empty.
func NewClient(baseURL, token string) (*Client, error) {
	if baseURL == "" {
		// Auto-detect Kubernetes API server URL from environment
		baseURL = "https://kubernetes.default.svc"
	}
	
	if token == "" {
		// Try to read token from service account mount
		var err error
		token, err = readServiceAccountToken()
		if err != nil {
			return nil, fmt.Errorf("cannot read service account token: %w", err)
		}
	}
	
	// Read CA certificate for secure API communication
	caCert, err := readServiceAccountCA()
	if err != nil {
		return nil, fmt.Errorf("cannot read service account CA: %w", err)
	}
	
	// Create transport with proper TLS configuration
	transport, err := createTransport(caCert)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP transport: %w", err)
	}
	
	return &Client{
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		baseURL: baseURL,
		token:   token,
		caCert:  caCert,
	}, nil
}

// GetPods retrieves pods from the given namespace (empty means all namespaces)
func (c *Client) GetPods(ctx context.Context, namespace string) ([]Pod, error) {
	url := fmt.Sprintf("%s/api/v1/pods", c.baseURL)
	if namespace != "" {
		url = fmt.Sprintf("%s/api/v1/namespaces/%s/pods", c.baseURL, namespace)
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+c.token)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get pods, status code: %d", resp.StatusCode)
	}
	
	var podList PodList
	if err := json.NewDecoder(resp.Body).Decode(&podList); err != nil {
		return nil, err
	}
	
	return podList.Items, nil
}

// Pod represents a Kubernetes Pod
type Pod struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		UID         string            `json:"uid"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	
	Status struct {
		Phase     string `json:"phase"`
		HostIP    string `json:"hostIP"`
		PodIP     string `json:"podIP"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		ContainerStatuses []struct {
			Name        string `json:"name"`
			ContainerID string `json:"containerID"`
			Ready       bool   `json:"ready"`
			RestartCount int   `json:"restartCount"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

// PodList represents a list of Kubernetes Pods
type PodList struct {
	Items []Pod `json:"items"`
}

// Helper functions omitted for brevity...
```

## Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Incomplete Metrics Support | Medium | Prioritize implementing the most commonly used metrics and establish a clear path for feature extension |
| Performance Overhead | Medium | Optimize through caching and parallel processing, provide parameters to adjust thread counts and intervals |
| Compatibility with Existing Configurations | High | Maintain support for traditional configuration, allow using both approaches simultaneously |
| API Permission Requirements | Medium | Clearly document RBAC permission requirements, provide minimal permission templates |
| Cluster Version Compatibility | Low | Test against Kubernetes 1.16+, document version compatibility |

## Implementation Progress

**Phase 1 - Basic Framework** (1-2 weeks)
- [x] Design collector interfaces
- [ ] Implement main command-line parameters
- [ ] Create collector manager framework

**Phase 2 - Core Collectors** (2-3 weeks)
- [ ] Implement node metrics collector
- [ ] Implement container metrics collector
- [ ] Implement Kubernetes state collector
- [ ] Implement application auto-discovery

**Phase 3 - Integration and Testing** (1-2 weeks)
- [ ] Integrate all collectors into vmagent
- [ ] Create tests for various cluster types
- [ ] Benchmark and performance optimization

**Phase 4 - Documentation and Release** (1 week)
- [ ] Create detailed documentation
- [ ] Create example dashboards
- [ ] Prepare release plan

## Test Plan

### Prerequisite testing updates

Before implementing this feature, we need to establish baseline benchmarks for performance comparison:

- Resource usage (CPU, memory) of current vmagent without Kubernetes monitoring
- Collection latency with traditional configurations using node-exporter, cadvisor, and kube-state-metrics
- Coverage of metrics in traditional setup
- Reliability metrics (error rates, collection failures)

### Unit tests

Unit tests will cover:

- Configuration parsing for various collector parameters
- Metric registration and deregistration
- Collector lifecycle management (initialization, start, stop)
- Validity of generated metric names and labels
- Error handling in collection code paths
- Concurrency safety of collectors

Each collector will have dedicated test suites:

- Node collector: Tests for CPU, memory, filesystem, network metrics
- Container collector: Tests for container metadata, resource usage metrics
- Kubernetes state collector: Tests for object state tracking, API interactions
- Auto-discovery: Tests for annotations parsing, role configuration

### Integration tests

Integration tests will verify:

- End-to-end metric collection in containerized environments
- Interaction with Kubernetes API server using mock clients
- Performance under various load conditions
- Configuration reload and dynamic reconfiguration
- Compatibility with various Kubernetes versions (1.16+)
- Multiple collectors working together

### e2e tests

End-to-end tests will be run on real Kubernetes clusters to validate:

- Collection accuracy compared to traditional tools
- Resource consumption (should be lower than combined tools)
- Scalability with large cluster sizes (100+ nodes)
- Fault tolerance (node failures, API server unavailability)
- Upgrade and downgrade scenarios
- Completeness of collected metrics for dashboard rendering

## Graduation Criteria

### Alpha

Alpha release requirements:

- Complete implementation of all core collectors
- Basic documentation and usage examples
- Functioning end-to-end on standard Kubernetes environments
- Unit test coverage >70%
- Performance at least equal to traditional setup
- Support for the most common metrics (80/20 rule)
- Clearly documented limitations and known issues

### Beta

Beta release requirements:

- Successfully running in at least 3 production environments
- Comprehensive documentation, including troubleshooting guides
- Performance optimizations complete
- Unit test coverage >85%
- Integration and e2e test coverage >60%
- Dashboard templates available for major observability platforms
- Alert rule templates available
- No known critical bugs
- Graceful degradation under error conditions

### Stable

Stable release requirements:

- Production usage for 3+ months without major issues
- Complete documentation, including reference dashboards and best practices
- Performance benchmarks showing improvement over traditional setup
- Unit test coverage >90%, integration and e2e test coverage >75%
- Telemetry for usage and error reporting
- Compatibility with all supported Kubernetes versions
- Verified upgrade path from beta
- Feature complete for targeted use cases

## Deprecated

Features that will be deprecated as part of this implementation:

- Complex manual kubernetes_sd_config configurations (replaced by simplified parameters)
- Manual service discovery configuration for common Kubernetes components
- Direct dependencies on external monitoring components (node-exporter, cadvisor, kube-state-metrics)

The traditional configuration approach will still be available but marked as legacy in documentation.

## Disabled

The feature will be disabled by default and requires explicit opt-in via the `-promscrape.kubernetes=true` flag. 

Individual collectors can be enabled or disabled through the `-promscrape.kubernetes.collectors` parameter.

## Upgrade / Downgrade Strategy

### Upgrade Strategy

For upgrades to versions with this feature:

1. Deploy new vmagent version with Kubernetes monitoring disabled
2. Verify normal operation
3. Enable Kubernetes monitoring with only non-critical collectors (node, container)
4. Validate collected metrics and dashboard rendering
5. Enable remaining collectors
6. Once validated, remove redundant components (node-exporter, cadvisor, kube-state-metrics)

### Downgrade Strategy

For downgrades from versions with this feature:

1. Deploy traditional monitoring components alongside vmagent
2. Verify they're working correctly
3. Disable Kubernetes monitoring in vmagent
4. Downgrade vmagent version

### Version Skew Strategy

In environments with multiple vmagent versions:

- Ensure metrics naming consistency with configuration
- Use metric relabeling to harmonize differences if needed
- Maintain backward compatibility in metric naming where possible
- Document potential conflicts and mitigation

## Production Readiness Review Questionnaire

### Feature Enablement and Rollback

1. **How can this feature be enabled / disabled in a live cluster?**
   - Feature gate: `-promscrape.kubernetes=true|false`
   - Other flags: Individual collectors can be enabled/disabled separately
   - Can be changed at runtime? No, requires restart of vmagent

2. **Does enabling the feature change any default behavior?**
   - Yes, it adds automatic discovery and collection of Kubernetes metrics
   - No changes when disabled

3. **Can the feature be disabled once it has been enabled?**
   - Yes, by setting `-promscrape.kubernetes=false`
   - Requires restart of vmagent

4. **What happens if we disable the feature while it's in use?**
   - Kubernetes metrics will no longer be collected
   - Existing metrics in storage will remain until retention period

5. **Are there any prerequisites for enabling this feature?**
   - RBAC permissions for vmagent to access Kubernetes API
   - Access to container runtime statistics
   - Access to node filesystem for node metrics

### Rollout, Upgrade and Rollback Planning

1. **How can an operator determine if the feature is in use?**
   - Check for presence of metrics from the collectors (node_*, container_*, kube_*)
   - Look for log messages indicating Kubernetes monitoring is enabled
   - Monitor resource usage patterns typical of active collectors

2. **How can an operator determine if the feature is enabled but not in use?**
   - Monitor for log messages about failed initialization
   - Check for absence of expected metrics despite enabling the feature
   - Verify error counters in vmagent's own metrics

3. **What are the SLIs for this feature?**
   - Latency: Metric collection duration
   - Availability: Percentage of successful scrapes
   - Errors: Rate of collection errors
   - Resource usage: CPU and memory consumption

4. **What are reasonable SLOs for the above SLIs?**
   - Latency: 99% of scrapes complete within 5s
   - Availability: 99.9% successful scrapes
   - Errors: <0.1% error rate
   - Resource usage: <200MB base + 2MB per node

5. **Are there any known limitations?**
   - Not all metrics from traditional exporters will be available
   - Performance may degrade in very large clusters (1000+ nodes)
   - Some specialized metrics require custom configuration

### Monitoring Requirements

1. **How can an operator monitor the feature?**
   - Monitor vmagent's own metrics for collector performance
   - Watch for collection errors in logs
   - Monitor resource usage of vmagent pods
   - Check for expected metric presence and freshness

2. **What are the reasonable alerting thresholds?**
   - Alert on >5% error rate in collection
   - Alert on persistent absence of critical metrics
   - Alert on collection latency exceeding 10s
   - Alert on vmagent resource saturation

3. **Are there any missing metrics that would be useful?**
   - Per-collector success/failure rates
   - API request counts and latencies
   - Metric cardinality statistics
   - Cache hit/miss rates

### Dependencies

1. **Does this feature depend on any specific services running in the cluster?**
   - Kubernetes API server
   - Kubelet on each node
   - Container runtime with stats API

2. **Does this feature depend on any other features?**
   - General Prometheus scraping functionality in vmagent
   - Service account and RBAC support in Kubernetes

3. **Does this feature make use of any API Extensions?**
   - No new API extensions are required

### Scalability

1. **Will enabling this feature result in any new API calls?**
   - Yes, calls to Kubernetes API for listing and watching resources
   - Kubelet API calls for container stats
   - Filesystem access for node stats

2. **Will enabling this feature result in introducing new API types?**
   - No new API types are introduced

3. **Will enabling this feature result in any new calls to cloud provider?**
   - No direct cloud provider API calls

4. **Will enabling this feature result in increasing size or count of the existing API objects?**
   - No change to API object size
   - No creation of additional API objects

5. **Will enabling this feature result in increasing time taken by any operations?**
   - Startup time of vmagent will increase slightly
   - No impact on Kubernetes control plane operations

6. **Will enabling this feature result in any new cardinality of metrics?**
   - Yes, new metrics with label dimensions for Kubernetes objects
   - Controlled through resource selection and namespaces filtering

### Troubleshooting

1. **How does this feature react if the API server and/or etcd is unavailable?**
   - Falls back to cached data for previously discovered resources
   - Continues collecting metrics that don't require API server
   - Logs errors and increments error counters
   - Retries with backoff for API server operations

2. **What are other known failure modes?**
   - Insufficient permissions: Logs authorization errors
   - Resource constraints: Collection slows or fails under resource pressure
   - Configuration errors: Logs parsing errors and uses defaults
   - Container runtime API changes: May fail to collect container metrics

3. **What steps should be taken if SLOs are not being met?**
   - Check vmagent logs for specific error messages
   - Verify RBAC permissions are correct
   - Consider reducing enabled collectors or increasing resources
   - Check for Kubernetes API server performance issues
   - Reduce collection frequency if necessary

## Implementation History

- **2025-03-17**: Initial VEP draft created

## Drawbacks

Potential drawbacks of this approach include:

1. **Increased complexity in vmagent**: Adding builtin collectors increases code complexity and maintenance burden
2. **Potential resource usage**: While more efficient than multiple components, still requires resources on each node
3. **Less flexibility**: Simplified approach may not cover all custom monitoring scenarios
4. **More permissions required**: vmagent needs broader permissions to collect all metrics
5. **Consistency challenges**: Maintaining consistent metrics during version transitions

## Alternatives

Alternative approaches that were considered:

1. **Operator-based approach**: Create a Kubernetes operator to manage monitoring components
   - Pros: Declarative configuration, managed lifecycle
   - Cons: Another component to maintain, doesn't simplify collection

2. **Push-based approach**: Have Kubernetes components push metrics to VictoriaMetrics
   - Pros: Reduced scrape complexity, potentially lower latency
   - Cons: Counter to Prometheus model, requires changes to components

  
## References

1. [GitHub issue #1393: Automatically discover and scrape Prometheus targets in Kubernetes](https://github.com/VictoriaMetrics/VictoriaMetrics/issues/1393)
2. [Prometheus Documentation: kubernetes_sd_config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config)
3. [Kubernetes Documentation: Monitoring Architecture](https://kubernetes.io/docs/concepts/cluster-administration/monitoring/)
4. [Node Exporter GitHub Repository](https://github.com/prometheus/node_exporter)
5. [cAdvisor GitHub Repository](https://github.com/google/cadvisor)
6. [kube-state-metrics GitHub Repository](https://github.com/kubernetes/kube-state-metrics) 