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
      - [Container Collector Implementation](#container-collector-implementation)
      - [Kubernetes State Collector Implementation](#kubernetes-state-collector-implementation)
      - [Auto-Discovery Implementation](#auto-discovery-implementation)
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

2. **Multiple Component Dependencies**:
   - Requires separate deployment of kube-state-metrics
   - Requires cadvisor
   - Requires node-exporter
   - Requires configuration for application metrics scraping

3. **Resource Waste**: Many generated metrics are never used in dashboards or alerting rules

4. **Operational Complexity**: DevOps professionals often can only copy configuration snippets from the internet without understanding how the entire system works

By providing simple command-line parameters to enable standardized Kubernetes monitoring, we can greatly simplify this process while ensuring consistent metric naming and labeling conventions.

## Goals

1. Provide a simple command-line flag `-promscrape.kubernetes=true` to enable Kubernetes monitoring
2. Support flexible selection of monitoring components through the `-promscrape.kubernetes.collectors` parameter
3. Integrate lightweight alternative components to eliminate dependencies on node-exporter, cadvisor, and kube-state-metrics
4. Establish unified metric naming and labeling conventions
5. Simplify automatic discovery and collection of application metrics
6. Reduce collection of unnecessary metrics to lower resource consumption
7. Provide official Kubernetes monitoring dashboards and alerting rules

## Non-Goals

1. Completely replicate all metrics from traditional components
2. Support all possible Kubernetes monitoring scenarios and configuration options
3. Replace advanced custom monitoring requirements

## Proposal

### Architecture Design

vmagent will be deployed as a DaemonSet on each node in the Kubernetes cluster, integrating the following functionalities:

1. **Node Metrics Collector**: Replaces node-exporter, collecting node-level metrics
2. **Container Metrics Collector**: Replaces cadvisor, collecting container-level metrics
3. **Kubernetes State Metrics Collector**: Replaces kube-state-metrics, collecting cluster object states
4. **Application Auto-Discovery**: Automatically discovers and scrapes application metrics based on annotations
5. **Unified Metrics Handling**: Standardizes metric names and labels

### Command Line Parameters Design

```bash
# Core switch
-promscrape.kubernetes=true                          # Main switch: Enable Kubernetes monitoring functionality

# Collector control
-promscrape.kubernetes.collectors=node,container,kube-state,app  # Specify enabled collectors

# Node collector parameters
-promscrape.kubernetes.node.enabled=true               # Enable node collector
-promscrape.kubernetes.node.interval="15s"             # Collection interval
-promscrape.kubernetes.node.collectors="all"           # Collect all metrics (default)
# Or select specific collectors
-promscrape.kubernetes.node.collectors="cpu,meminfo,filesystem,netdev,loadavg,diskstats"

# Container collector parameters
-promscrape.kubernetes.container.enabled=true          # Enable container collector
-promscrape.kubernetes.container.interval="15s"        # Collection interval
-promscrape.kubernetes.container.collectors="all"      # Collect all metrics (default)
-promscrape.kubernetes.container.useCache=true         # Use cache to improve performance
-promscrape.kubernetes.container.workers=5             # Number of parallel worker threads

# Kubernetes state collector parameters
-promscrape.kubernetes.kube-state.enabled=true         # Enable kube-state collector
-promscrape.kubernetes.kube-state.interval="30s"       # Collection interval
-promscrape.kubernetes.kube-state.resources="all"      # Collect all resources (default)
-promscrape.kubernetes.kube-state.namespaces=""        # Limit to namespaces, empty means all
-promscrape.kubernetes.kube-state.excludeNamespaces="" # Excluded namespaces

# Application auto-discovery parameters
-promscrape.kubernetes.autoDiscover.enabled=true       # Enable auto-discovery functionality
-promscrape.kubernetes.autoDiscover.interval="30s"     # Discovery refresh interval
-promscrape.kubernetes.autoDiscover.roles="pod,service,node,endpoints,ingress"  # Enabled service discovery roles
-promscrape.kubernetes.autoDiscover.pod.pathAnnotation="victoriametrics.com/path"  # Metrics path annotation
-promscrape.kubernetes.autoDiscover.pod.portAnnotation="victoriametrics.com/port"  # Metrics port annotation
-promscrape.kubernetes.autoDiscover.pod.schemeAnnotation="victoriametrics.com/scheme"  # Protocol annotation
```

### Built-in Collectors Design

#### 1. Node Metrics Collector

A lightweight node-exporter alternative that collects key node metrics:

- CPU usage
- Memory usage
- Filesystem space
- Network throughput
- System load

Key metrics examples:
```
vm_node_cpu_usage_percent{cpu="0", mode="user"} 24.5
vm_node_memory_bytes{type="used"} 8053063680
vm_node_memory_bytes{type="total"} 16106127360
vm_node_filesystem_bytes{device="/dev/sda1", mountpoint="/", fstype="ext4", type="used"} 52034642240
vm_node_network_bytes_total{device="eth0", direction="receive"} 1234567890
vm_node_load1 0.42
```

#### 2. Container Metrics Collector

An efficient cadvisor alternative that collects container resource usage metrics:

- Container CPU usage and limits
- Container memory usage and limits
- Container network usage
- Container disk I/O

Key metrics examples:
```
vm_container_cpu_usage_seconds_total{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default"} 15.7
vm_container_memory_usage_bytes{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default", type="used"} 67108864
vm_container_memory_usage_bytes{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default", type="limit"} 134217728
vm_container_cpu_throttling_seconds_total{container_id="8af9f2", container_name="nginx", pod_name="web-1", namespace="default"} 0.45
```

#### 3. Kubernetes State Metrics Collector

An efficient kube-state-metrics alternative that collects Kubernetes object states:

- Pod status and counts
- Deployment status and replica counts
- Node status and conditions
- Service and endpoint information

Key metrics examples:
```
vm_kube_pod_status{namespace="default", pod="web-1", phase="Running", host_ip="10.0.0.5", pod_ip="10.244.0.17"} 1
vm_kube_deployment_status{namespace="default", deployment="web", status_type="replicas"} 3
vm_kube_deployment_status{namespace="default", deployment="web", status_type="available"} 3
vm_kube_deployment_status{namespace="default", deployment="web", status_type="ready"} 3
vm_kube_node_status{node="worker-1", condition="Ready", status="true"} 1
```

#### 4. Application Auto-Discovery

Auto-discovers and scrapes application metrics based on annotations:

- Uses `victoriametrics.com/scrape: "true"` annotation to mark scrapable Pods
- Configures scrape details through `victoriametrics.com/path`, `victoriametrics.com/port`, `victoriametrics.com/scheme` annotations
- Supports role-based service discovery: pod, service, node, endpoints, ingress

### Implementation

#### Collector Interface

```go
// pkg/kubernetes/collector/collector.go

package collector

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Collector defines the interface that all Kubernetes metric collectors must implement
type Collector interface {
	// Name returns the unique name of the collector
	Name() string

	// Description returns the description of the collector
	Description() string

	// Initialize initializes the collector and registers all metrics
	Initialize(registry prometheus.Registerer) error

	// Start starts the collector's run loop, returning a Stop function
	Start(ctx context.Context) (StopFunc, error)

	// CollectorType returns the collector type (node, container, kube-state, app)
	CollectorType() string

	// SetInterval sets the collection interval
	SetInterval(interval time.Duration)
}

// StopFunc is used to stop the collector
type StopFunc func()

// Config represents the configuration options for a collector
type Config struct {
	// Enabled indicates whether the collector is enabled
	Enabled bool

	// Interval represents the collection interval
	Interval time.Duration

	// CollectorsEnabled represents the specific collectors enabled (e.g., cpu, memory, etc.)
	CollectorsEnabled []string

	// UseCache indicates whether to use caching
	UseCache bool

	// Workers represents the number of worker threads
	Workers int

	// Resources represents the resource types to monitor
	Resources []string

	// Namespaces represents the namespaces to monitor
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
	kubernetesEnabled = flag.Bool("promscrape.kubernetes", false, "Whether to enable Kubernetes monitoring")
	
	kubernetesCollectors = flag.String("promscrape.kubernetes.collectors", "node,container,kube-state,app", 
		"List of collectors to enable, comma-separated. Available values: node, container, kube-state, app, all")
)

func main() {
	// Parse command line arguments
	flag.Parse()

	// Other vmagent initialization code...

	// If Kubernetes monitoring is enabled, initialize the Kubernetes monitoring module
	if *kubernetesEnabled {
		log.Printf("Enabling Kubernetes monitoring with collectors: %s", *kubernetesCollectors)
		
		// Create Kubernetes monitoring manager
		k8sMgr, err := kubernetes.NewManager(*kubernetesCollectors)
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
```

#### Node Collector Implementation

```go
// pkg/kubernetes/node/collector.go

package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/net"
	
	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/kubernetes/collector"
)

// Collector implements node metrics collection
type Collector struct {
	// Context and lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	interval   time.Duration
	
	// Performance optimization
	metricCache  map[string]float64
	mutex        sync.RWMutex
	
	// Enabled collectors
	enabledCollectors map[string]bool
	
	// Metric definitions
	cpuUsage      *prometheus.GaugeVec
	memoryStats   *prometheus.GaugeVec
	diskSpace     *prometheus.GaugeVec
	diskIO        *prometheus.GaugeVec
	networkIO     *prometheus.GaugeVec
	loadAvg       *prometheus.GaugeVec
	
	// Performance metrics
	scrapeDuration  prometheus.Histogram
	scrapeErrors    prometheus.Counter
}

// NewCollector creates a new node collector
func NewCollector(config collector.Config) (*Collector, error) {
	// Set default collectors
	enabledCollectors := make(map[string]bool)
	if len(config.CollectorsEnabled) == 0 || containsString(config.CollectorsEnabled, "all") {
		// Enable all collectors by default
		enabledCollectors = map[string]bool{
			"cpu": true, "meminfo": true, "filesystem": true,
			"netdev": true, "loadavg": true, "diskstats": true,
		}
	} else {
		// Only enable specified collectors
		for _, c := range config.CollectorsEnabled {
			enabledCollectors[c] = true
		}
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Collector{
		ctx:              ctx,
		cancel:           cancel,
		interval:         config.Interval,
		metricCache:      make(map[string]float64),
		enabledCollectors: enabledCollectors,
	}, nil
}

// Name returns the collector name
func (c *Collector) Name() string {
	return "node-collector"
}

// Description returns the collector description
func (c *Collector) Description() string {
	return "Collects node-level system metrics, replacing node-exporter"
}

// CollectorType returns the collector type
func (c *Collector) CollectorType() string {
	return "node"
}

// SetInterval sets the collection interval
func (c *Collector) SetInterval(interval time.Duration) {
	c.interval = interval
}

// Initialize initializes the collector and registers metrics
func (c *Collector) Initialize(registry prometheus.Registerer) error {
	// Create CPU metrics
	c.cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vm_node_cpu_usage_percent",
			Help: "CPU usage percentage by mode",
		},
		[]string{"cpu", "mode"},
	)
	
	// Create memory metrics
	c.memoryStats = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vm_node_memory_bytes",
			Help: "Memory statistics in bytes",
		},
		[]string{"type"},  // types: total, used, free, cached, buffers, etc.
	)
	
	// Create disk space metrics
	c.diskSpace = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vm_node_filesystem_bytes",
			Help: "Filesystem statistics in bytes",
		},
		[]string{"device", "mountpoint", "fstype", "type"},  // types: size, used, free, etc.
	)
	
	// Create disk IO metrics
	c.diskIO = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vm_node_disk_io_bytes_total",
			Help: "Total disk IO bytes",
		},
		[]string{"device", "direction"},  // direction: read, write
	)
	
	// Create network IO metrics
	c.networkIO = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vm_node_network_bytes_total",
			Help: "Network traffic statistics in bytes",
		},
		[]string{"device", "direction"},  // direction: receive, transmit
	)
	
	// Create load metrics
	c.loadAvg = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vm_node_load",
			Help: "System load average",
		},
		[]string{"period"},  // period: 1m, 5m, 15m
	)
	
	// Create performance metrics
	c.scrapeDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "vm_node_collector_scrape_duration_seconds",
			Help:    "Node metrics collection duration",
			Buckets: prometheus.DefBuckets,
		},
	)
	
	c.scrapeErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "vm_node_collector_scrape_errors_total",
			Help: "Total number of node collector errors",
		},
	)
	
	// Only register metrics for enabled collectors
	if c.enabledCollectors["cpu"] {
		registry.MustRegister(c.cpuUsage)
	}
	if c.enabledCollectors["meminfo"] {
		registry.MustRegister(c.memoryStats)
	}
	if c.enabledCollectors["filesystem"] {
		registry.MustRegister(c.diskSpace)
	}
	if c.enabledCollectors["diskstats"] {
		registry.MustRegister(c.diskIO)
	}
	if c.enabledCollectors["netdev"] {
		registry.MustRegister(c.networkIO)
	}
	if c.enabledCollectors["loadavg"] {
		registry.MustRegister(c.loadAvg)
	}
	
	// Always register performance metrics
	registry.MustRegister(c.scrapeDuration, c.scrapeErrors)
	
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
				if err := c.collect(); err != nil {
					c.scrapeErrors.Inc()
				}
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

// collect performs a complete metrics collection
func (c *Collector) collect() error {
	start := time.Now()
	defer func() {
		c.scrapeDuration.Observe(time.Since(start).Seconds())
	}()
	
	// Use multiple goroutines to collect different types of metrics in parallel
	var wg sync.WaitGroup
	errCh := make(chan error, 5)  // Buffer for potential errors
	
	// Collect CPU metrics
	if c.enabledCollectors["cpu"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.collectCPUMetrics(); err != nil {
				errCh <- err
			}
		}()
	}
	
	// Collect memory metrics
	if c.enabledCollectors["meminfo"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.collectMemoryMetrics(); err != nil {
				errCh <- err
			}
		}()
	}
	
	// Collect filesystem metrics
	if c.enabledCollectors["filesystem"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.collectFilesystemMetrics(); err != nil {
				errCh <- err
			}
		}()
	}
	
	// Collect disk IO metrics
	if c.enabledCollectors["diskstats"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.collectDiskIOMetrics(); err != nil {
				errCh <- err
			}
		}()
	}
	
	// Collect network metrics
	if c.enabledCollectors["netdev"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.collectNetworkMetrics(); err != nil {
				errCh <- err
			}
		}()
	}
	
	// Collect load metrics
	if c.enabledCollectors["loadavg"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.collectLoadMetrics(); err != nil {
				errCh <- err
			}
		}()
	}
	
	// Wait for all collection tasks to complete
	wg.Wait()
	close(errCh)
	
	// Check for errors
	var lastErr error
	for err := range errCh {
		lastErr = err
	}
	
	return lastErr
}

// collectCPUMetrics collects CPU-related metrics
func (c *Collector) collectCPUMetrics() error {
	// Get CPU usage with minimal overhead
	cpuPercents, err := cpu.PercentWithContext(c.ctx, 0, true)
	if err != nil {
		return err
	}
	
	// Update metrics in batch
	for i, percent := range cpuPercents {
		cpuID := fmt.Sprintf("cpu%d", i)
		c.cpuUsage.WithLabelValues(cpuID, "user").Set(percent)
	}
	
	return nil
}

// collectMemoryMetrics collects memory-related metrics
func (c *Collector) collectMemoryMetrics() error {
	memStats, err := mem.VirtualMemoryWithContext(c.ctx)
	if err != nil {
		return err
	}
	
	c.memoryStats.WithLabelValues("total").Set(float64(memStats.Total))
	c.memoryStats.WithLabelValues("used").Set(float64(memStats.Used))
	c.memoryStats.WithLabelValues("free").Set(float64(memStats.Free))
	c.memoryStats.WithLabelValues("cached").Set(float64(memStats.Cached))
	c.memoryStats.WithLabelValues("buffers").Set(float64(memStats.Buffers))
	
	return nil
}

// Other collector methods omitted for brevity...

// containsString checks if a string slice contains a specific string
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
```

#### Container Collector Implementation

```go
// pkg/kubernetes/container/collector.go

package container

import (
	"context"
	"sync"
	"time"
	
	"github.com/prometheus/client_golang/prometheus"
	"github.com/docker/docker/client"
	"github.com/docker/docker/api/types"
	
	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/kubernetes/collector"
)

// Collector implements container metrics collection
type Collector struct {
	// Context and lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	interval   time.Duration
	
	// Client connections
	dockerClient *client.Client
	
	// Cache settings
	useCache      bool
	containerCache map[string]*containerInfo
	mutex          sync.RWMutex
	
	// Worker count
	workers int
	
	// Enabled collectors
	enabledCollectors map[string]bool
	
	// Metric definitions
	cpuUsage        *prometheus.GaugeVec
	cpuThrottling   *prometheus.GaugeVec
	memoryUsage     *prometheus.GaugeVec
	memoryFailures  *prometheus.GaugeVec
	networkUsage    *prometheus.GaugeVec
	diskIO          *prometheus.GaugeVec
	containerState  *prometheus.GaugeVec
	
	// Performance metrics
	scrapeDuration    prometheus.Histogram
	scrapeErrors      prometheus.Counter
	containersScraped prometheus.Gauge
}

// containerInfo holds cached container metadata
type containerInfo struct {
	ID          string
	Name        string
	PodName     string
	Namespace   string
	LastSeen    time.Time
	Labels      map[string]string
}

// Implementation details omitted for brevity...
```

#### Kubernetes State Collector Implementation

```go
// pkg/kubernetes/kube-state/collector.go

package kubestate

import (
	"context"
	"sync"
	"time"
	
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/client-go/informers"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	
	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/kubernetes/collector"
)

// Collector implements Kubernetes state metrics collection
type Collector struct {
	// Context and lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	interval   time.Duration
	
	// Kubernetes client and caches
	client          kubernetes.Interface
	informerFactory informers.SharedInformerFactory
	
	// Work queue
	workqueue  workqueue.RateLimitingInterface
	workers    int
	
	// Monitored resource types
	resources        map[string]bool
	namespaces       []string
	excludeNamespaces []string
	
	// Metric definitions
	podMetrics       *prometheus.GaugeVec
	deploymentMetrics *prometheus.GaugeVec
	nodeMetrics      *prometheus.GaugeVec
	serviceMetrics   *prometheus.GaugeVec
	pvcMetrics       *prometheus.GaugeVec
	
	// Performance metrics
	scrapeLatency    prometheus.Histogram
	apiErrors        prometheus.Counter
	resourcesScraped prometheus.CounterVec
}

// Implementation details omitted for brevity...
```

#### Auto-Discovery Implementation

```go
// pkg/kubernetes/autodiscover/collector.go

package autodiscover

import (
	"context"
	"sync"
	"time"
	
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/apimachinery/pkg/util/yaml"
	
	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/kubernetes/collector"
	"github.com/VictoriaMetrics/VictoriaMetrics/pkg/promscrape"
)

// Collector implements Kubernetes application auto-discovery
type Collector struct {
	// Context and lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	interval   time.Duration
	
	// Kubernetes client
	client     kubernetes.Interface
	
	// Configuration
	roles             []string
	podConfig         RoleConfig
	serviceConfig     RoleConfig
	nodeConfig        RoleConfig
	endpointsConfig   RoleConfig
	ingressConfig     RoleConfig
	
	// Performance metrics
	discoveredTargets prometheus.GaugeVec
	scrapeErrors      prometheus.Counter
	scrapeLatency     prometheus.Histogram
}

// Implementation details omitted for brevity...
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
   - Check for presence of vm_* metrics from the collectors
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