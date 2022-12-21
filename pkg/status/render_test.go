// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package status

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatStatus(t *testing.T) {
	tz := os.Getenv("TZ")
	os.Setenv("TZ", "GMT")
	defer os.Setenv("TZ", tz)

	t.Run("invalid JSON", func(t *testing.T) {
		actual, err := FormatStatus([]byte(`-`))
		assert.Nil(t, err)
		want := `
====================
Status render errors
====================
  invalid character ' ' in numeric literal


`
		assert.Equal(t, want, actual)
	})

	t.Run("success", func(t *testing.T) {
		actual, err := FormatStatus([]byte(agentStatusJSON))
		assert.Nil(t, err)
		want := `
==============
Agent (vx.y.z)
==============

  Status date: 2022-12-20 22:52:01.796 GMT (1671576721796)
  Agent start: 2022-12-20 19:21:27.793 GMT (1671564087793)
  Pid: 12136
  Go Version: go1.18.8
  Python Version: 3.8.14
  Build arch: amd64
  Agent flavor: agent
  Check Runners: 4
  Log Level: INFO

  Paths
  =====
    Config File: /etc/datadog-agent/datadog.yaml
    conf.d: /etc/datadog-agent/conf.d
    checks.d: /etc/datadog-agent/checks.d

  Clocks
  ======
    NTP offset: 35µs
    System time: 2022-12-20 22:52:01.796 GMT (1671576721796)

  Host Info
  =========
    bootTime: 2022-12-20 19:19:03 GMT (1671563943000)
    hostId: d23fb05c-2393-9a7a-fbf3-92cd755df12a
    kernelArch: x86_64
    kernelVersion: 5.10.133+
    os: linux
    platform: cos
    platformVersion: 97
    procs: 211
    uptime: 2m37s
    virtualizationRole: guest

  Hostnames
  =========
    cluster-name: dd-sandbox
    host_aliases: [gke-dd-sandbox-bits-8943422b-5wpg-dd-sandbox gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal gke-dd-sandbox-bits-8943422b-5wpg.datadog-sandbox]
    hostname: gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal
    socket-fqdn: dd-datadog-c4kcx
    socket-hostname: dd-datadog-c4kcx
    host tags:
      cluster_name:dd-sandbox
      kube_cluster_name:dd-sandbox
      zone:asia-northeast1-a
      internal-hostname:gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal
      instance-id:90825865558996083
      project:datadog-sandbox
      numeric_project_id:958371799887
      cluster-name:dd-sandbox
      cluster-uid:3d6b7737edf6489fb1927577e24e8b0e314e6826aa3e47fa9b2eae419f261013
      cluster-location:asia-northeast1
    hostname provider: gce
    unused hostname providers:
      'hostname' configuration/environment: hostname is empty
      'hostname_file' configuration/environment: 'hostname_file' configuration is not enabled
      fargate: agent is not runnning on Fargate

  Metadata
  ========
    agent_version: x.y.z
    cloud_provider: GCP
    config_apm_dd_url: 
    config_dd_url: 
    config_logs_dd_url: 
    config_logs_socks5_proxy_address: 
    config_no_proxy: []
    config_process_dd_url: 
    config_proxy_http: 
    config_proxy_https: 
    config_site: 
    feature_apm_enabled: false
    feature_cspm_enabled: false
    feature_cws_enabled: false
    feature_logs_enabled: true
    feature_networks_enabled: false
    feature_networks_http_enabled: false
    feature_networks_https_enabled: false
    feature_otlp_enabled: false
    feature_process_enabled: false
    feature_processes_container_enabled: true
    flavor: agent
    hostname_source: gce
    install_method_installer_version: datadog-3.6.4
    install_method_tool: helm
    install_method_tool_version: Helm
    logs_transport: TCP

=========
Collector
=========

  Running Checks
  ==============
    
    cilium (2.3.0)
    --------------
      Instance ID: cilium:bac99095d52d45c [ERROR]
      Configuration Source: file:/etc/datadog-agent/conf.d/cilium.d/auto_conf.yaml
      Total Runs: 842
      Metric Samples: Last Run: 0, Total: 0
      Events: Last Run: 0, Total: 0
      Service Checks: Last Run: 1, Total: 842
      Average Execution Time : 8ms
      Last Execution Date : 2022-12-20 22:51:54 GMT (1671576714000)
      Last Successful Execution Date : Never
      Error: HTTPConnectionPool(host='10.146.15.207', port=9090): Max retries exceeded with url: /metrics (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f20296ba430>: Failed to establish a new connection: [Errno 111] Connection refused'))
      Traceback (most recent call last):
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py", line 174, in _new_conn
          conn = connection.create_connection(
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/util/connection.py", line 95, in create_connection
          raise err
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/util/connection.py", line 85, in create_connection
          sock.connect(sa)
      ConnectionRefusedError: [Errno 111] Connection refused
      
      During handling of the above exception, another exception occurred:
      
      Traceback (most recent call last):
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connectionpool.py", line 703, in urlopen
          httplib_response = self._make_request(
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connectionpool.py", line 398, in _make_request
          conn.request(method, url, **httplib_request_kw)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py", line 239, in request
          super(HTTPConnection, self).request(method, url, body=body, headers=headers)
        File "/opt/datadog-agent/embedded/lib/python3.8/http/client.py", line 1256, in request
          self._send_request(method, url, body, headers, encode_chunked)
        File "/opt/datadog-agent/embedded/lib/python3.8/http/client.py", line 1302, in _send_request
          self.endheaders(body, encode_chunked=encode_chunked)
        File "/opt/datadog-agent/embedded/lib/python3.8/http/client.py", line 1251, in endheaders
          self._send_output(message_body, encode_chunked=encode_chunked)
        File "/opt/datadog-agent/embedded/lib/python3.8/http/client.py", line 1011, in _send_output
          self.send(msg)
        File "/opt/datadog-agent/embedded/lib/python3.8/http/client.py", line 951, in send
          self.connect()
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py", line 205, in connect
          conn = self._new_conn()
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py", line 186, in _new_conn
          raise NewConnectionError(
      urllib3.exceptions.NewConnectionError: <urllib3.connection.HTTPConnection object at 0x7f20296ba430>: Failed to establish a new connection: [Errno 111] Connection refused
      
      During handling of the above exception, another exception occurred:
      
      Traceback (most recent call last):
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/adapters.py", line 489, in send
          resp = conn.urlopen(
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connectionpool.py", line 787, in urlopen
          retries = retries.increment(
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/util/retry.py", line 592, in increment
          raise MaxRetryError(_pool, url, error or ResponseError(cause))
      urllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='10.146.15.207', port=9090): Max retries exceeded with url: /metrics (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f20296ba430>: Failed to establish a new connection: [Errno 111] Connection refused'))
      
      During handling of the above exception, another exception occurred:
      
      Traceback (most recent call last):
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/base.py", line 1122, in run
          self.check(instance)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/base_check.py", line 142, in check
          self.process(scraper_config)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py", line 573, in process
          for metric in self.scrape_metrics(scraper_config):
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py", line 500, in scrape_metrics
          response = self.poll(scraper_config)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py", line 837, in poll
          response = self.send_request(endpoint, scraper_config, headers)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py", line 863, in send_request
          return http_handler.get(endpoint, stream=True, **kwargs)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/utils/http.py", line 356, in get
          return self._request('get', url, options)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/utils/http.py", line 420, in _request
          response = self.make_request_aia_chasing(request_method, method, url, new_options, persist)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/utils/http.py", line 426, in make_request_aia_chasing
          response = request_method(url, **new_options)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/api.py", line 73, in get
          return request("get", url, params=params, **kwargs)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/api.py", line 59, in request
          return session.request(method=method, url=url, **kwargs)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/sessions.py", line 587, in request
          resp = self.send(prep, **send_kwargs)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/sessions.py", line 701, in send
          r = adapter.send(request, **kwargs)
        File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/adapters.py", line 565, in send
          raise ConnectionError(e, request=request)
      requests.exceptions.ConnectionError: HTTPConnectionPool(host='10.146.15.207', port=9090): Max retries exceeded with url: /metrics (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f20296ba430>: Failed to establish a new connection: [Errno 111] Connection refused'))
    
    datadog_cluster_agent (2.4.0)
    -----------------------------
      Instance ID: datadog_cluster_agent:4b0f56c49d48c92e [OK]
      Configuration Source: file:/etc/datadog-agent/conf.d/datadog_cluster_agent.d/auto_conf.yaml
      Total Runs: 842
      Metric Samples: Last Run: 125, Total: 104,832
      Events: Last Run: 0, Total: 0
      Service Checks: Last Run: 1, Total: 842
      Average Execution Time : 29ms
      Last Execution Date : 2022-12-20 22:52:01 GMT (1671576721000)
      Last Successful Execution Date : 2022-12-20 22:52:01 GMT (1671576721000)
      
      Instance ID: datadog_cluster_agent:79dc7329a0398f09 [OK]
      Configuration Source: file:/etc/datadog-agent/conf.d/datadog_cluster_agent.d/auto_conf.yaml
      Total Runs: 838
      Metric Samples: Last Run: 61, Total: 50,672
      Events: Last Run: 0, Total: 0
      Service Checks: Last Run: 1, Total: 838
      Average Execution Time : 25ms
      Last Execution Date : 2022-12-20 22:51:59 GMT (1671576719000)
      Last Successful Execution Date : 2022-12-20 22:51:59 GMT (1671576719000)
      
    
    network (2.9.2)
    ---------------
      Instance ID: network:d884b5186b651429 [OK]
      Configuration Source: file:/etc/datadog-agent/conf.d/network.d/conf.yaml.default
      Total Runs: 841
      Metric Samples: Last Run: 174, Total: 146,334
      Events: Last Run: 0, Total: 0
      Service Checks: Last Run: 0, Total: 0
      Average Execution Time : 6ms
      Last Execution Date : 2022-12-20 22:51:48 GMT (1671576708000)
      Last Successful Execution Date : 2022-12-20 22:51:48 GMT (1671576708000)
      
  Check Initialization Errors
  ===========================

    
      postgres (13.1.0)
      -----------------

      instance 0:

        could not invoke 'postgres' python check constructor. New constructor API returned:
Traceback (most recent call last):
  File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/postgres.py", line 62, in __init__
    self._config = PostgresConfig(self.instance)
  File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/config.py", line 35, in __init__
    raise ConfigurationError('Please specify a user to connect to Postgres.')
datadog_checks.base.errors.ConfigurationError: Please specify a user to connect to Postgres.
Deprecated constructor API returned:
__init__() got an unexpected keyword argument 'agentConfig'
  Loading Errors
  ==============
    postgres
    --------
      Core Check Loader:
        Check postgres not found in Catalog
        
      JMX Check Loader:
        check is not a jmx check, or unable to determine if it's so
        
      Python Check Loader:
        could not configure check instance for python check postgres: could not invoke 'postgres' python check constructor. New constructor API returned:
Traceback (most recent call last):
  File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/postgres.py", line 62, in __init__
    self._config = PostgresConfig(self.instance)
  File "/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/config.py", line 35, in __init__
    raise ConfigurationError('Please specify a user to connect to Postgres.')
datadog_checks.base.errors.ConfigurationError: Please specify a user to connect to Postgres.
Deprecated constructor API returned:
__init__() got an unexpected keyword argument 'agentConfig'
        
========
JMXFetch
========

  Information
  ==================
  Initialized checks
  ==================
    no checks
    
  Failed checks
  =============
    no checks
    
=========
Forwarder
=========

  Transactions
  ============
    Cluster: 0
    ClusterRole: 0
    ClusterRoleBinding: 0
    CronJob: 0
    DaemonSet: 0
    Deployment: 0
    Dropped: 0
    HighPriorityQueueFull: 0
    Ingress: 0
    Job: 0
    Namespace: 0
    Node: 0
    PersistentVolume: 0
    PersistentVolumeClaim: 0
    Pod: 0
    ReplicaSet: 0
    Requeued: 0
    Retried: 0
    RetryQueueSize: 0
    Role: 0
    RoleBinding: 0
    Service: 0
    ServiceAccount: 0
    StatefulSet: 0

  Transaction Successes
  =====================
    Total number: 1775
    Successes By Endpoint:
      check_run_v1: 841
      intake: 72
      metadata_v1: 21
      series_v2: 841

  On-disk storage
  ===============
    On-disk storage is disabled. Configure ` + "`forwarder_storage_max_size_in_bytes`" + ` to enable it.

  API Keys status
  ===============
    API key ending with 841ae: API Key valid

==========
Endpoints
==========
  https://app.datadoghq.com - API Key ending with:
      - 841ae

==========
Logs Agent
==========
    Reliable: Sending uncompressed logs in SSL encrypted TCP to agent-intake.logs.datadoghq.com on port 10516

    You are currently sending Logs to Datadog through TCP (either because logs_config.force_use_tcp or logs_config.socks5_proxy_address is set or the HTTP connectivity test has failed). To benefit from increased reliability and better network performances, we strongly encourage switching over to compressed HTTPS which is now the default protocol.

    BytesSent: 1.8474997e+07
    EncodedBytesSent: 1.8474997e+07
    LogsProcessed: 10438
    LogsSent: 10438

  kube-system/pdcsi-node-vmxbk/gce-pd-driver
  ------------------------------------------
    - Type: file
      Identifier: 401a8645147ae8ef2baf2a5187c22b61554a64c5e0800b481c7a6a6e2e5e9d53
      Path: /var/log/pods/kube-system_pdcsi-node-vmxbk_8194ece2-46dd-495e-9220-3a6b88fa4d61/gce-pd-driver/*.log
      Service: gcp-compute-persistent-disk-csi-driver
      Source: gcp-compute-persistent-disk-csi-driver
      Status: OK
        1 files tailed out of 1 files matching
      Inputs:
        /var/log/pods/kube-system_pdcsi-node-vmxbk_8194ece2-46dd-495e-9220-3a6b88fa4d61/gce-pd-driver/0.log
      Average Latency (ms): 2280
      24h Average Latency (ms): 0
      Peak Latency (ms): 5473
      24h Peak Latency (ms): 0

  kube-system/l7-default-backend-6dc845c45d-xlnmh/default-http-backend
  --------------------------------------------------------------------
    - Type: file
      Identifier: 0f23fbf70ab6cb8063cacb65bf7c7472a6e4062838764cac256439070942f161
      Path: /var/log/pods/kube-system_l7-default-backend-6dc845c45d-xlnmh_85840891-57e7-4fd4-8c1d-9a7ec5227614/default-http-backend/*.log
      Service: ingress-gce-404-server-with-metrics
      Source: ingress-gce-404-server-with-metrics
      Status: OK
        1 files tailed out of 1 files matching
      Inputs:
        /var/log/pods/kube-system_l7-default-backend-6dc845c45d-xlnmh_85840891-57e7-4fd4-8c1d-9a7ec5227614/default-http-backend/0.log
      Average Latency (ms): 1365
      24h Average Latency (ms): 1365
      Peak Latency (ms): 5461
      24h Peak Latency (ms): 5461


=============
Process Agent
=============

  Version: x.y.z
  Status date: 2022-12-20 22:52:01.802 GMT (1671576721802)
  Process Agent Start: 2022-12-20 19:21:28.069 GMT (1671564088069)
  Pid: 12223
  Go Version: go1.18.8
  Build arch: amd64
  Log Level: INFO
  Enabled Checks: [container rtcontainer pod]
  Allocated Memory: 35,295,544 bytes
  Hostname: gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal

  =================
  Process Endpoints
  =================
    https://process.datadoghq.com - API Key ending with:
        - 841ae

  =========
  Collector
  =========
    Last collection time: 2022-12-20 22:51:56
    Docker socket: 
    Number of processes: 0
    Number of containers: 25
    Process Queue length: 0
    RTProcess Queue length: 0
    Connections Queue length: 0
    Event Queue length: 0
    Pod Queue length: 0
    Process Bytes enqueued: 0
    RTProcess Bytes enqueued: 0
    Connections Bytes enqueued: 0
    Event Bytes enqueued: 0
    Pod Bytes enqueued: 0
    Drop Check Payloads: []

=========
APM Agent
=========
  Status: Running
  Pid: 12174
  Uptime: 12633 seconds
  Mem alloc: 9,203,488 bytes
  Hostname: gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal
  Receiver: 0.0.0.0:8126
  Endpoints:
    https://trace.agent.datadoghq.com

  Receiver (previous minute)
  ==========================
    No traces received in the previous minute.
    

  Writer (previous minute)
  ========================
    Traces: 0 payloads, 0 traces, 0 events, 0 bytes
    Stats: 0 payloads, 0 stats buckets, 0 bytes

==========
Aggregator
==========
  Checks Metric Sample: 3,800,535
  Dogstatsd Metric Sample: 136,758
  Event: 1
  Events Flushed: 1
  Number Of Flushes: 841
  Series Flushed: 3,224,651
  Service Check: 25,700
  Service Checks Flushed: 26,509

=========
DogStatsD
=========
  Event Packets: 0
  Event Parse Errors: 0
  Metric Packets: 136,757
  Metric Parse Errors: 0
  Service Check Packets: 0
  Service Check Parse Errors: 0
  Udp Bytes: 21,336,530
  Udp Packet Reading Errors: 0
  Udp Packets: 76,232
  Uds Bytes: 0
  Uds Origin Detection Errors: 0
  Uds Packet Reading Errors: 0
  Uds Packets: 1
  Unterminated Metric Errors: 0
`
		assert.Equal(t, want, actual)
	})
}

// JSON with simplified actual `kubectl exec <DD_AGENT_POD> -- agent status -p`
const agentStatusJSON = `{
   "JMXStartupError":{
      "LastError":"",
      "Timestamp":0
   },
   "JMXStatus":{
      "checks":{
         "failed_checks":null,
         "initialized_checks":null
      },
      "errors":0,
      "info":null,
      "timestamp":0
   },
   "NoProxyChanged":{
      
   },
   "NoProxyIgnoredWarningMap":{
      
   },
   "NoProxyUsedInFuture":{
      
   },
   "TransportWarnings":false,
   "adConfigErrors":{
      
   },
   "adEnabledFeatures":{
      "containerd":{
         
      },
      "cri":{
         
      },
      "docker":{
         
      },
      "kubernetes":{
         
      }
   },
   "agent_metadata":{
      "agent_version":"x.y.z",
      "cloud_provider":"GCP",
      "config_apm_dd_url":"",
      "config_dd_url":"",
      "config_logs_dd_url":"",
      "config_logs_socks5_proxy_address":"",
      "config_no_proxy":[
         
      ],
      "config_process_dd_url":"",
      "config_proxy_http":"",
      "config_proxy_https":"",
      "config_site":"",
      "feature_apm_enabled":false,
      "feature_cspm_enabled":false,
      "feature_cws_enabled":false,
      "feature_logs_enabled":true,
      "feature_networks_enabled":false,
      "feature_networks_http_enabled":false,
      "feature_networks_https_enabled":false,
      "feature_otlp_enabled":false,
      "feature_process_enabled":false,
      "feature_processes_container_enabled":true,
      "flavor":"agent",
      "hostname_source":"gce",
      "install_method_installer_version":"datadog-3.6.4",
      "install_method_tool":"helm",
      "install_method_tool_version":"Helm",
      "logs_transport":"TCP"
   },
   "agent_start_nano":1671564087793439200,
   "aggregatorStats":{
      "ChecksHistogramBucketMetricSample":0,
      "ChecksMetricSample":3800535,
      "ContainerLifecycleEvents":0,
      "ContainerLifecycleEventsErrors":0,
      "DogstatsdContexts":93,
      "DogstatsdContextsByMtype":{
         "Count":0,
         "Counter":76,
         "Distribution":0,
         "Gauge":17,
         "Histogram":0,
         "Historate":0,
         "MonotonicCount":0,
         "Rate":0,
         "Set":0
      },
      "DogstatsdMetricSample":136758,
      "Event":1,
      "EventPlatformEvents":{
         
      },
      "EventPlatformEventsErrors":{
         
      },
      "EventsFlushErrors":0,
      "EventsFlushed":1,
      "Flush":{
         "ChecksMetricSampleFlushTime":{
            "FlushIndex":8,
            "Flushes":[
               44312071,
               42714488,
               42721563,
               42262456,
               39736079,
               49760988,
               28360194,
               40449840,
               49900928,
               41497721,
               40739343,
               41976327,
               42934731,
               42979442,
               33903960,
               39177109,
               43491512,
               50904228,
               29265025,
               43582513,
               44163028,
               47762416,
               31154709,
               43193587,
               41688206,
               44087559,
               31397914,
               41220369,
               49938925,
               44233483,
               41200705,
               41019926
            ],
            "LastFlush":49900928,
            "Name":"ChecksMetricSampleFlushTime"
         },
         "EventFlushTime":{
            "FlushIndex":0,
            "Flushes":[
               4647639,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0
            ],
            "LastFlush":4647639,
            "Name":"EventFlushTime"
         },
         "MainFlushTime":{
            "FlushIndex":8,
            "Flushes":[
               44334830,
               42749290,
               42754301,
               42291120,
               39767833,
               49787977,
               28384444,
               40473295,
               49931294,
               41520569,
               40771722,
               42005371,
               42966661,
               43010526,
               33931635,
               39201697,
               43524406,
               50929418,
               29292356,
               43611507,
               44194318,
               47785236,
               31178148,
               43221235,
               41715080,
               44114401,
               31473101,
               41249741,
               49969058,
               44263971,
               41224211,
               41046581
            ],
            "LastFlush":49931294,
            "Name":"MainFlushTime"
         },
         "ManifestsTime":{
            "FlushIndex":-1,
            "Flushes":[
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0
            ],
            "LastFlush":0,
            "Name":"ManifestsTime"
         },
         "MetricSketchFlushTime":{
            "FlushIndex":-1,
            "Flushes":[
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0
            ],
            "LastFlush":0,
            "Name":"MetricSketchFlushTime"
         },
         "ServiceCheckFlushTime":{
            "FlushIndex":8,
            "Flushes":[
               2058889,
               1920759,
               11507635,
               1674867,
               1658458,
               1434994,
               1450193,
               2151860,
               1513542,
               1980162,
               1934000,
               2263711,
               2053405,
               1880826,
               1882956,
               2094664,
               1609399,
               3797669,
               2294483,
               2673682,
               1911187,
               2732110,
               3557228,
               1458707,
               2108863,
               2190762,
               1743607,
               1960074,
               9607250,
               2044019,
               4845038,
               2028722
            ],
            "LastFlush":1513542,
            "Name":"ServiceCheckFlushTime"
         }
      },
      "FlushCount":{
         "Events":{
            "FlushIndex":0,
            "Flushes":[
               1,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0
            ],
            "LastFlush":1,
            "Name":"Events"
         },
         "Manifests":{
            "FlushIndex":-1,
            "Flushes":[
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0
            ],
            "LastFlush":0,
            "Name":"Manifests"
         },
         "Series":{
            "FlushIndex":8,
            "Flushes":[
               4102,
               4101,
               3070,
               4101,
               4102,
               4101,
               3070,
               4101,
               4120,
               4101,
               3070,
               4101,
               4102,
               4101,
               3070,
               4101,
               4102,
               4101,
               3070,
               4101,
               4102,
               4101,
               3070,
               4101,
               4102,
               4101,
               3070,
               4101,
               4102,
               4101,
               3070,
               4101
            ],
            "LastFlush":4120,
            "Name":"Series"
         },
         "ServiceChecks":{
            "FlushIndex":8,
            "Flushes":[
               33,
               33,
               27,
               33,
               33,
               33,
               27,
               33,
               35,
               33,
               27,
               33,
               33,
               33,
               27,
               33,
               33,
               33,
               27,
               33,
               33,
               33,
               27,
               33,
               33,
               33,
               27,
               33,
               33,
               33,
               27,
               33
            ],
            "LastFlush":35,
            "Name":"ServiceChecks"
         },
         "Sketches":{
            "FlushIndex":-1,
            "Flushes":[
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0,
               0
            ],
            "LastFlush":0,
            "Name":"Sketches"
         }
      },
      "HostnameUpdate":0,
      "MetricTags":{
         "Series":{
            "Above100":0,
            "Above90":0
         },
         "Sketches":{
            "Above100":0,
            "Above90":0
         }
      },
      "NumberOfFlush":841,
      "OrchestratorManifests":0,
      "OrchestratorManifestsErrors":0,
      "OrchestratorMetadata":0,
      "OrchestratorMetadataErrors":0,
      "SeriesFlushErrors":0,
      "SeriesFlushed":3224651,
      "ServiceCheck":25700,
      "ServiceCheckFlushErrors":0,
      "ServiceCheckFlushed":26509,
      "SketchesFlushErrors":0,
      "SketchesFlushed":0
   },
   "apmStats":{
      "Event":{
         
      },
      "ServiceCheck":{
         
      },
      "check_run_v1":0,
      "cmdline":[
         "trace-agent",
         "-config=/etc/datadog-agent/datadog.yaml"
      ],
      "config":{
         "AgentVersion":"x.y.z",
         "AnalyzedRateByServiceLegacy":{
            
         },
         "AnalyzedSpansByService":{
            
         },
         "BucketInterval":10000000000,
         "ConfigPath":"/etc/datadog-agent/datadog.yaml",
         "ConnectionLimit":0,
         "ConnectionResetInterval":0,
         "ContainerProcRoot":"/host/proc",
         "DDAgentBin":"/opt/datadog-agent/bin/agent/agent",
         "DebuggerProxy":{
            "APIKey":"",
            "DDURL":""
         },
         "DefaultEnv":"none",
         "EVPProxy":{
            "APIKey":"",
            "AdditionalEndpoints":null,
            "ApplicationKey":"",
            "DDURL":"",
            "Enabled":true,
            "MaxPayloadSize":5242880
         },
         "Enabled":true,
         "Endpoints":[
            {
               "Host":"https://trace.agent.datadoghq.com",
               "NoProxy":false
            }
         ],
         "ErrorTPS":10,
         "ExtraAggregators":null,
         "ExtraSampleRate":1,
         "FargateOrchestrator":"Unknown",
         "GUIPort":"-1",
         "GitCommit":"9b0b54b",
         "GlobalTags":{
            
         },
         "Hostname":"gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
         "Ignore":{
            
         },
         "LogFilePath":"/var/log/datadog/trace-agent.log",
         "LogThrottling":true,
         "MaxCPU":0,
         "MaxCatalogEntries":5000,
         "MaxEPS":200,
         "MaxMemory":0,
         "MaxRemoteTPS":100,
         "MaxRequestBytes":52428800,
         "OTLPReceiver":{
            "BindHost":"0.0.0.0",
            "GRPCPort":0,
            "HTTPPort":0,
            "MaxRequestBytes":52428800,
            "SpanNameAsResourceName":false,
            "SpanNameRemappings":{
               
            },
            "UsePreviewHostnameLogic":true
         },
         "Obfuscation":{
            "CreditCards":{
               "Enabled":false,
               "Luhn":false
            },
            "ES":{
               "Enabled":false,
               "KeepValues":null,
               "ObfuscateSQLValues":null
            },
            "HTTP":{
               "remove_path_digits":false,
               "remove_query_string":false
            },
            "Memcached":{
               "Enabled":false
            },
            "Mongo":{
               "Enabled":false,
               "KeepValues":null,
               "ObfuscateSQLValues":null
            },
            "Redis":{
               "Enabled":false
            },
            "RemoveStackTraces":false,
            "SQLExecPlan":{
               "Enabled":false,
               "KeepValues":null,
               "ObfuscateSQLValues":null
            },
            "SQLExecPlanNormalize":{
               "Enabled":false,
               "KeepValues":null,
               "ObfuscateSQLValues":null
            }
         },
         "PipeBufferSize":1000000,
         "PipeSecurityDescriptor":"D:AI(A;;GA;;;WD)",
         "ProfilingProxy":{
            "AdditionalEndpoints":null,
            "DDURL":""
         },
         "ProxyURL":null,
         "RareSamplerCardinality":200,
         "RareSamplerCooldownPeriod":300000000000,
         "RareSamplerEnabled":false,
         "RareSamplerTPS":5,
         "ReceiverHost":"0.0.0.0",
         "ReceiverPort":8126,
         "ReceiverSocket":"/var/run/datadog/apm.socket",
         "ReceiverTimeout":0,
         "RejectTags":null,
         "RemoteSamplingClient":null,
         "ReplaceTags":null,
         "RequireTags":null,
         "Site":"datadoghq.com",
         "SkipSSLValidation":false,
         "StatsWriter":{
            "ConnectionLimit":0,
            "FlushPeriodSeconds":0,
            "QueueSize":0
         },
         "StatsdEnabled":true,
         "StatsdHost":"localhost",
         "StatsdPipeName":"",
         "StatsdPort":8125,
         "StatsdSocket":"/var/run/datadog/dsd.socket",
         "SynchronousFlushing":false,
         "TargetTPS":10,
         "TelemetryConfig":{
            "Enabled":true,
            "Endpoints":[
               {
                  "Host":"https://instrumentation-telemetry-intake.datadoghq.com",
                  "NoProxy":false
               }
            ]
         },
         "TraceWriter":{
            "ConnectionLimit":0,
            "FlushPeriodSeconds":0,
            "QueueSize":0
         },
         "WatchdogInterval":10000000000,
         "WindowsPipeName":""
      },
      "connections":0,
      "container":0,
      "events_v2":0,
      "forwarder":{
         "APIKeyFailure":{
            
         },
         "APIKeyStatus":{
            
         },
         "FileStorage":{
            "CurrentSizeInBytes":0,
            "DeserializeCount":0,
            "DeserializeErrorsCount":0,
            "DeserializeTransactionsCount":0,
            "FileSize":0,
            "FilesCount":0,
            "FilesRemovedCount":0,
            "PointsDroppedCount":0,
            "SerializeCount":0,
            "StartupReloadedRetryFilesCount":0
         },
         "RemovalPolicy":{
            "FilesFromUnknownDomainCount":0,
            "NewRemovalPolicyCount":0,
            "OutdatedFilesCount":0,
            "RegisteredDomainCount":0
         },
         "TransactionContainer":{
            "CurrentMemSizeInBytes":0,
            "ErrorsCount":0,
            "PointsDroppedCount":0,
            "TransactionsCount":0,
            "TransactionsDroppedCount":0
         },
         "Transactions":{
            "Cluster":0,
            "ClusterRole":0,
            "ClusterRoleBinding":0,
            "ConnectionEvents":{
               "ConnectSuccess":0,
               "DNSSuccess":0
            },
            "CronJob":0,
            "DaemonSet":0,
            "Deployment":0,
            "Dropped":0,
            "DroppedByEndpoint":{
               
            },
            "Errors":0,
            "ErrorsByType":{
               "ConnectionErrors":0,
               "DNSErrors":0,
               "SentRequestErrors":0,
               "TLSErrors":0,
               "WroteRequestErrors":0
            },
            "HTTPErrors":0,
            "HTTPErrorsByCode":{
               
            },
            "HighPriorityQueueFull":0,
            "Ingress":0,
            "InputBytesByEndpoint":{
               
            },
            "InputCountByEndpoint":{
               
            },
            "Job":0,
            "Namespace":0,
            "Node":0,
            "PersistentVolume":0,
            "PersistentVolumeClaim":0,
            "Pod":0,
            "ReplicaSet":0,
            "Requeued":0,
            "RequeuedByEndpoint":{
               
            },
            "Retried":0,
            "RetriedByEndpoint":{
               
            },
            "RetryQueueSize":0,
            "Role":0,
            "RoleBinding":0,
            "Service":0,
            "ServiceAccount":0,
            "StatefulSet":0,
            "Success":0,
            "SuccessByEndpoint":{
               "check_run_v1":0,
               "connections":0,
               "container":0,
               "events_v2":0,
               "host_metadata_v2":0,
               "intake":0,
               "orchestrator":0,
               "process":0,
               "rtcontainer":0,
               "rtprocess":0,
               "series_v1":0,
               "series_v2":0,
               "services_checks_v2":0,
               "sketches_v1":0,
               "sketches_v2":0,
               "validate_v1":0
            },
            "SuccessBytesByEndpoint":{
               
            }
         }
      },
      "host_metadata_v2":0,
      "hostname":{
         "errors":{
            
         },
         "provider":""
      },
      "intake":0,
      "kubeletQueries":0,
      "memstats":{
         "Alloc":9203488,
         "BuckHashSys":1476356,
         "BySize":[
            {
               "Frees":0,
               "Mallocs":0,
               "Size":0
            },
            {
               "Frees":6491,
               "Mallocs":8217,
               "Size":8
            },
            {
               "Frees":67312,
               "Mallocs":75056,
               "Size":16
            },
            {
               "Frees":17587,
               "Mallocs":19581,
               "Size":24
            },
            {
               "Frees":32176,
               "Mallocs":34336,
               "Size":32
            },
            {
               "Frees":193085,
               "Mallocs":200869,
               "Size":48
            },
            {
               "Frees":29796,
               "Mallocs":31522,
               "Size":64
            },
            {
               "Frees":4749,
               "Mallocs":5157,
               "Size":80
            },
            {
               "Frees":7468,
               "Mallocs":8379,
               "Size":96
            },
            {
               "Frees":19380,
               "Mallocs":20190,
               "Size":112
            },
            {
               "Frees":5828,
               "Mallocs":6064,
               "Size":128
            },
            {
               "Frees":858,
               "Mallocs":966,
               "Size":144
            },
            {
               "Frees":2574,
               "Mallocs":2876,
               "Size":160
            },
            {
               "Frees":520,
               "Mallocs":640,
               "Size":176
            },
            {
               "Frees":5251,
               "Mallocs":5300,
               "Size":192
            },
            {
               "Frees":10604,
               "Mallocs":10819,
               "Size":208
            },
            {
               "Frees":574,
               "Mallocs":585,
               "Size":224
            },
            {
               "Frees":52,
               "Mallocs":63,
               "Size":240
            },
            {
               "Frees":2526,
               "Mallocs":2607,
               "Size":256
            },
            {
               "Frees":1420,
               "Mallocs":2374,
               "Size":288
            },
            {
               "Frees":385,
               "Mallocs":439,
               "Size":320
            },
            {
               "Frees":166,
               "Mallocs":282,
               "Size":352
            },
            {
               "Frees":5110,
               "Mallocs":5174,
               "Size":384
            },
            {
               "Frees":3857,
               "Mallocs":4001,
               "Size":416
            },
            {
               "Frees":167,
               "Mallocs":228,
               "Size":448
            },
            {
               "Frees":10,
               "Mallocs":21,
               "Size":480
            },
            {
               "Frees":1928,
               "Mallocs":1964,
               "Size":512
            },
            {
               "Frees":149,
               "Mallocs":253,
               "Size":576
            },
            {
               "Frees":277,
               "Mallocs":339,
               "Size":640
            },
            {
               "Frees":65,
               "Mallocs":104,
               "Size":704
            },
            {
               "Frees":5603,
               "Mallocs":5621,
               "Size":768
            },
            {
               "Frees":4661,
               "Mallocs":4713,
               "Size":896
            },
            {
               "Frees":1022,
               "Mallocs":1046,
               "Size":1024
            },
            {
               "Frees":80,
               "Mallocs":128,
               "Size":1152
            },
            {
               "Frees":171,
               "Mallocs":226,
               "Size":1280
            },
            {
               "Frees":47,
               "Mallocs":66,
               "Size":1408
            },
            {
               "Frees":3811,
               "Mallocs":3824,
               "Size":1536
            },
            {
               "Frees":25,
               "Mallocs":61,
               "Size":1792
            },
            {
               "Frees":23,
               "Mallocs":2101,
               "Size":2048
            },
            {
               "Frees":28,
               "Mallocs":43,
               "Size":2304
            },
            {
               "Frees":104,
               "Mallocs":166,
               "Size":2688
            },
            {
               "Frees":3784,
               "Mallocs":3808,
               "Size":3072
            },
            {
               "Frees":8,
               "Mallocs":12,
               "Size":3200
            },
            {
               "Frees":16,
               "Mallocs":18,
               "Size":3456
            },
            {
               "Frees":1814,
               "Mallocs":1846,
               "Size":4096
            },
            {
               "Frees":30,
               "Mallocs":41,
               "Size":4864
            },
            {
               "Frees":46,
               "Mallocs":112,
               "Size":5376
            },
            {
               "Frees":2525,
               "Mallocs":2540,
               "Size":6144
            },
            {
               "Frees":2,
               "Mallocs":3,
               "Size":6528
            },
            {
               "Frees":3,
               "Mallocs":4,
               "Size":6784
            },
            {
               "Frees":0,
               "Mallocs":0,
               "Size":6912
            },
            {
               "Frees":6,
               "Mallocs":23,
               "Size":8192
            },
            {
               "Frees":13,
               "Mallocs":23,
               "Size":9472
            },
            {
               "Frees":0,
               "Mallocs":1,
               "Size":9728
            },
            {
               "Frees":2,
               "Mallocs":2,
               "Size":10240
            },
            {
               "Frees":27,
               "Mallocs":33,
               "Size":10880
            },
            {
               "Frees":1264,
               "Mallocs":1267,
               "Size":12288
            },
            {
               "Frees":7,
               "Mallocs":8,
               "Size":13568
            },
            {
               "Frees":0,
               "Mallocs":1,
               "Size":14336
            },
            {
               "Frees":3,
               "Mallocs":8,
               "Size":16384
            },
            {
               "Frees":2,
               "Mallocs":4,
               "Size":18432
            }
         ],
         "DebugGC":false,
         "EnableGC":true,
         "Frees":452206,
         "GCCPUFraction":0.000006711103007073701,
         "GCSys":5610160,
         "HeapAlloc":9203488,
         "HeapIdle":4349952,
         "HeapInuse":11673600,
         "HeapObjects":30693,
         "HeapReleased":2768896,
         "HeapSys":16023552,
         "LastGC":1671576699279998200,
         "Lookups":0,
         "MCacheInuse":4800,
         "MCacheSys":15600,
         "MSpanInuse":199648,
         "MSpanSys":212160,
         "Mallocs":482899,
         "NextGC":18734736,
         "NumForcedGC":0,
         "NumGC":112,
         "OtherSys":895140,
         "PauseEnd":[
            1671564087913256700,
            1671564087931454700,
            1671564087943871500,
            1671564087955040800,
            1671564087968827600,
            1671564088992134000,
            1671564090175674400,
            1671564210179202800,
            1671564330281137000,
            1671564450391639800,
            1671564570482766000,
            1671564690579483100,
            1671564810679497200,
            1671564930780055600,
            1671565050881695700,
            1671565170969689600,
            1671565290978055400,
            1671565410980104000,
            1671565531079493600,
            1671565651180879000,
            1671565771280284400,
            1671565891379562000,
            1671566011479317800,
            1671566131579652600,
            1671566251679999200,
            1671566371779553500,
            1671566491879266000,
            1671566611969548800,
            1671566731979780400,
            1671566852079728600,
            1671566972178231600,
            1671567092279900200,
            1671567212379593500,
            1671567332479513900,
            1671567452579419400,
            1671567572679608800,
            1671567692780085500,
            1671567812879591700,
            1671567932969137700,
            1671568052979455700,
            1671568173079828500,
            1671568293179548000,
            1671568413279783400,
            1671568533379503000,
            1671568653480081400,
            1671568773579647700,
            1671568893679734800,
            1671569013779564800,
            1671569133879878700,
            1671569253969943600,
            1671569373979546000,
            1671569494079854800,
            1671569614178650600,
            1671569734281099000,
            1671569854379951400,
            1671569974479769600,
            1671570094579894000,
            1671570214679492600,
            1671570334779478800,
            1671570454879744300,
            1671570574969515300,
            1671570694981150200,
            1671570815079357700,
            1671570935179836000,
            1671571055280081200,
            1671571175379725000,
            1671571295479606500,
            1671571415579779600,
            1671571535679800300,
            1671571655781140700,
            1671571775879445200,
            1671571895969722600,
            1671572015979468500,
            1671572136080494600,
            1671572256178413600,
            1671572376279462000,
            1671572496381176800,
            1671572616479518000,
            1671572736579679700,
            1671572856679630300,
            1671572976779828000,
            1671573096879709000,
            1671573216969567200,
            1671573336979494700,
            1671573457079943000,
            1671573577179470600,
            1671573697281018600,
            1671573817379453700,
            1671573937479360500,
            1671574057579859200,
            1671574177679952000,
            1671574297779749400,
            1671574417879844600,
            1671574537902974700,
            1671574657920277500,
            1671574777969677800,
            1671574897980053500,
            1671575018079575800,
            1671575138133448200,
            1671575258178515700,
            1671575378279752400,
            1671575498380484600,
            1671575618479927000,
            1671575738579916800,
            1671575858679406000,
            1671575978779872500,
            1671576098879517400,
            1671576218969406200,
            1671576338977824500,
            1671576459079446800,
            1671576579180034800,
            1671576699279998200,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
         ],
         "PauseNs":[
            46413,
            31669,
            204868,
            117345,
            74007,
            89412,
            105282,
            139001,
            79855,
            2981053,
            639363,
            135560,
            115529,
            138504,
            175967,
            220198,
            132252,
            128540,
            127661,
            165500,
            323911,
            170575,
            120570,
            138680,
            121879,
            134396,
            123380,
            141659,
            141620,
            136333,
            143611,
            138283,
            128446,
            152163,
            125872,
            138600,
            231282,
            135068,
            149158,
            134220,
            157271,
            139776,
            126038,
            170892,
            123525,
            135293,
            126271,
            135075,
            151281,
            160865,
            168662,
            144485,
            137813,
            159136,
            147859,
            189494,
            127434,
            139900,
            126271,
            174845,
            129258,
            173941,
            129854,
            164270,
            149586,
            161772,
            128515,
            138944,
            129054,
            142686,
            132583,
            179613,
            133061,
            194225,
            140911,
            172765,
            178647,
            137185,
            134585,
            215003,
            131651,
            144303,
            138492,
            133629,
            175695,
            153123,
            132663,
            139171,
            135641,
            175922,
            134977,
            134222,
            134897,
            142459,
            150645,
            205936,
            153958,
            154496,
            611337,
            144868,
            152040,
            143210,
            182191,
            149947,
            145851,
            130828,
            155130,
            148684,
            133767,
            134360,
            133709,
            151741,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
         ],
         "PauseTotalNs":20075872,
         "StackInuse":753664,
         "StackSys":753664,
         "Sys":24986632,
         "TotalAlloc":110362624
      },
      "orchestrator":0,
      "orchestrator-cache":{
         "Cluster":0,
         "ClusterRole":0,
         "ClusterRoleBinding":0,
         "CronJob":0,
         "DaemonSet":0,
         "Deployment":0,
         "Ingress":0,
         "Job":0,
         "Namespace":0,
         "Node":0,
         "PersistentVolume":0,
         "PersistentVolumeClaim":0,
         "Pod":0,
         "ReplicaSet":0,
         "Role":0,
         "RoleBinding":0,
         "Service":0,
         "ServiceAccount":0,
         "StatefulSet":0
      },
      "orchestrator-sends":{
         "Cluster":0,
         "ClusterRole":0,
         "ClusterRoleBinding":0,
         "CronJob":0,
         "DaemonSet":0,
         "Deployment":0,
         "Ingress":0,
         "Job":0,
         "Namespace":0,
         "Node":0,
         "PersistentVolume":0,
         "PersistentVolumeClaim":0,
         "Pod":0,
         "ReplicaSet":0,
         "Role":0,
         "RoleBinding":0,
         "Service":0,
         "ServiceAccount":0,
         "StatefulSet":0
      },
      "pid":12174,
      "process":0,
      "ratebyservice":{
         
      },
      "ratebyservice_filtered":{
         
      },
      "ratelimiter":{
         "RecentPayloadsSeen":0,
         "RecentTracesDropped":0,
         "RecentTracesSeen":0,
         "TargetRate":1
      },
      "receiver":[
         
      ],
      "rtcontainer":0,
      "rtprocess":0,
      "serializer":{
         "SendEventsErrItemTooBigs":0,
         "SendEventsErrItemTooBigsFallback":0
      },
      "series":{
         
      },
      "series_v1":0,
      "series_v2":0,
      "services_checks_v2":0,
      "sketch_series":{
         "ItemTooBig":0,
         "PayloadFull":0,
         "UnexpectedItemDrops":0
      },
      "sketches_v1":0,
      "sketches_v2":0,
      "splitter":{
         "NotTooBig":0,
         "PayloadDrops":0,
         "TooBig":0,
         "TotalLoops":0
      },
      "stats_writer":{
         "Bytes":0,
         "ClientPayloads":0,
         "Errors":0,
         "Payloads":0,
         "Retries":0,
         "Splits":0,
         "StatsBuckets":0,
         "StatsEntries":0
      },
      "trace_writer":{
         "Bytes":0,
         "BytesUncompressed":0,
         "Errors":0,
         "Events":0,
         "Payloads":0,
         "Retries":0,
         "SingleMaxSize":0,
         "Spans":0,
         "Traces":0
      },
      "uptime":12633,
      "validate_v1":0,
      "version":{
         "GitCommit":"9b0b54b",
         "Version":"x.y.z"
      },
      "watchdog":{
         "CPU":{
            "UserAvg":0.001333347035207443
         },
         "Mem":{
            "Alloc":9123672
         }
      }
   },
   "autoConfigStats":{
      "ConfigErrors":{
         
      },
      "ResolveWarnings":{
         "datadog_cluster_agent":[
            "error resolving template datadog_cluster_agent for service containerd://ca53986d6ed6efc147e22f17ae96b78037e46d3a5c5aaaafbf3495238cba9d8c: unable to resolve, service not ready"
         ],
         "envoy":[
            "error resolving template envoy for service containerd://9867242c450acde5dd828717e07126768683c7613a8f172b942f76eb73e61b99: unable to resolve, service not ready"
         ],
         "istio":[
            "error resolving template istio for service containerd://9867242c450acde5dd828717e07126768683c7613a8f172b942f76eb73e61b99: unable to resolve, service not ready",
            "error resolving template istio for service containerd://9867242c450acde5dd828717e07126768683c7613a8f172b942f76eb73e61b99: unable to resolve, service not ready"
         ],
         "openmetrics":[
            "error resolving template openmetrics for service containerd://9867242c450acde5dd828717e07126768683c7613a8f172b942f76eb73e61b99: unable to resolve, service not ready",
            "error resolving template openmetrics for service containerd://9867242c450acde5dd828717e07126768683c7613a8f172b942f76eb73e61b99: unable to resolve, service not ready",
            "error resolving template openmetrics for service containerd://9867242c450acde5dd828717e07126768683c7613a8f172b942f76eb73e61b99: unable to resolve, service not ready"
         ]
      }
   },
   "build_arch":"amd64",
   "checkSchedulerStats":{
      "LoaderErrors":{
         "postgres":{
            "Core Check Loader":"Check postgres not found in Catalog",
            "JMX Check Loader":"check is not a jmx check, or unable to determine if it's so",
            "Python Check Loader":"could not configure check instance for python check postgres: could not invoke 'postgres' python check constructor. New constructor API returned:\nTraceback (most recent call last):\n  File \"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/postgres.py\", line 62, in __init__\n    self._config = PostgresConfig(self.instance)\n  File \"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/config.py\", line 35, in __init__\n    raise ConfigurationError('Please specify a user to connect to Postgres.')\ndatadog_checks.base.errors.ConfigurationError: Please specify a user to connect to Postgres.\nDeprecated constructor API returned:\n__init__() got an unexpected keyword argument 'agentConfig'"
         }
      },
      "RunErrors":{
         
      }
   },
   "clusterAgentStatus":{
      "Endpoint":"https://10.122.58.252:5005",
      "Version":"x.y.z+commit.9b0b54b"
   },
   "complianceChecks":{
      
   },
   "conf_file":"/etc/datadog-agent/datadog.yaml",
   "config":{
      "additional_checksd":"/etc/datadog-agent/checks.d",
      "confd_path":"/etc/datadog-agent/conf.d",
      "fips_enabled":"false",
      "fips_local_address":"localhost",
      "fips_port_range_start":"3833",
      "log_file":"",
      "log_level":"INFO"
   },
   "dogstatsdStats":{
      "EventPackets":0,
      "EventParseErrors":0,
      "MetricPackets":136757,
      "MetricParseErrors":0,
      "ServiceCheckPackets":0,
      "ServiceCheckParseErrors":0,
      "UdpBytes":21336530,
      "UdpPacketReadingErrors":0,
      "UdpPackets":76232,
      "UdsBytes":0,
      "UdsOriginDetectionErrors":0,
      "UdsPacketReadingErrors":0,
      "UdsPackets":1,
      "UnterminatedMetricErrors":0
   },
   "endpointsInfos":{
      "https://app.datadoghq.com":[
         "841ae"
      ]
   },
   "filterErrors":{
      
   },
   "flavor":"agent",
   "forwarderStats":{
      "APIKeyFailure":{
         
      },
      "APIKeyStatus":{
         "API key ending with 841ae":"API Key valid"
      },
      "FileStorage":{
         "CurrentSizeInBytes":0,
         "DeserializeCount":0,
         "DeserializeErrorsCount":0,
         "DeserializeTransactionsCount":0,
         "FileSize":0,
         "FilesCount":0,
         "FilesRemovedCount":0,
         "PointsDroppedCount":0,
         "SerializeCount":0,
         "StartupReloadedRetryFilesCount":0
      },
      "RemovalPolicy":{
         "FilesFromUnknownDomainCount":0,
         "NewRemovalPolicyCount":0,
         "OutdatedFilesCount":0,
         "RegisteredDomainCount":0
      },
      "TransactionContainer":{
         "CurrentMemSizeInBytes":0,
         "ErrorsCount":0,
         "PointsDroppedCount":0,
         "TransactionsCount":0,
         "TransactionsDroppedCount":0
      },
      "Transactions":{
         "Cluster":0,
         "ClusterRole":0,
         "ClusterRoleBinding":0,
         "ConnectionEvents":{
            "ConnectSuccess":1,
            "DNSSuccess":1
         },
         "CronJob":0,
         "DaemonSet":0,
         "Deployment":0,
         "Dropped":0,
         "DroppedByEndpoint":{
            
         },
         "Errors":0,
         "ErrorsByType":{
            "ConnectionErrors":0,
            "DNSErrors":0,
            "SentRequestErrors":0,
            "TLSErrors":0,
            "WroteRequestErrors":0
         },
         "HTTPErrors":0,
         "HTTPErrorsByCode":{
            
         },
         "HighPriorityQueueFull":0,
         "Ingress":0,
         "InputBytesByEndpoint":{
            "check_run_v1":996200,
            "intake":115387,
            "metadata_v1":24099,
            "series_v2":131870299
         },
         "InputCountByEndpoint":{
            "check_run_v1":841,
            "intake":72,
            "metadata_v1":21,
            "series_v2":841
         },
         "Job":0,
         "Namespace":0,
         "Node":0,
         "PersistentVolume":0,
         "PersistentVolumeClaim":0,
         "Pod":0,
         "ReplicaSet":0,
         "Requeued":0,
         "RequeuedByEndpoint":{
            
         },
         "Retried":0,
         "RetriedByEndpoint":{
            
         },
         "RetryQueueSize":0,
         "Role":0,
         "RoleBinding":0,
         "Service":0,
         "ServiceAccount":0,
         "StatefulSet":0,
         "Success":1775,
         "SuccessByEndpoint":{
            "check_run_v1":841,
            "connections":0,
            "container":0,
            "events_v2":0,
            "host_metadata_v2":0,
            "intake":72,
            "metadata_v1":21,
            "orchestrator":0,
            "process":0,
            "rtcontainer":0,
            "rtprocess":0,
            "series_v1":0,
            "series_v2":841,
            "services_checks_v2":0,
            "sketches_v1":0,
            "sketches_v2":0,
            "validate_v1":0
         },
         "SuccessBytesByEndpoint":{
            "check_run_v1":996200,
            "intake":115387,
            "metadata_v1":24099,
            "series_v2":131870299
         }
      }
   },
   "go_version":"go1.18.8",
   "hostTags":[
      "cluster_name:dd-sandbox",
      "kube_cluster_name:dd-sandbox",
      "zone:asia-northeast1-a",
      "internal-hostname:gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
      "instance-id:90825865558996083",
      "project:datadog-sandbox",
      "numeric_project_id:958371799887",
      "cluster-name:dd-sandbox",
      "cluster-uid:3d6b7737edf6489fb1927577e24e8b0e314e6826aa3e47fa9b2eae419f261013",
      "cluster-location:asia-northeast1"
   ],
   "hostinfo":{
      "bootTime":1671563943,
      "hostId":"d23fb05c-2393-9a7a-fbf3-92cd755df12a",
      "hostname":"dd-datadog-c4kcx",
      "kernelArch":"x86_64",
      "kernelVersion":"5.10.133+",
      "os":"linux",
      "platform":"cos",
      "platformFamily":"",
      "platformVersion":"97",
      "procs":211,
      "uptime":157,
      "virtualizationRole":"guest",
      "virtualizationSystem":""
   },
   "hostnameStats":{
      "errors":{
         "'hostname' configuration/environment":"hostname is empty",
         "'hostname_file' configuration/environment":"'hostname_file' configuration is not enabled",
         "fargate":"agent is not runnning on Fargate"
      },
      "provider":"gce"
   },
   "inventories":{
      "envoy:c41fa57fd37dd81a":{
         "version.major":"1",
         "version.minor":"20",
         "version.patch":"1",
         "version.raw":"1.20.1",
         "version.scheme":"semver"
      }
   },
   "logsStats":{
      "endpoints":[
         "Reliable: Sending uncompressed logs in SSL encrypted TCP to agent-intake.logs.datadoghq.com on port 10516"
      ],
      "errors":[
         
      ],
      "integrations":[
         {
            "name":"kube-system/pdcsi-node-vmxbk/gce-pd-driver",
            "sources":[
               {
                  "all_time_avg_latency":2280,
                  "all_time_peak_latency":5473,
                  "bytes_read":3690,
                  "configuration":{
                     "Identifier":"401a8645147ae8ef2baf2a5187c22b61554a64c5e0800b481c7a6a6e2e5e9d53",
                     "Path":"/var/log/pods/kube-system_pdcsi-node-vmxbk_8194ece2-46dd-495e-9220-3a6b88fa4d61/gce-pd-driver/*.log",
                     "Service":"gcp-compute-persistent-disk-csi-driver",
                     "Source":"gcp-compute-persistent-disk-csi-driver"
                  },
                  "info":{
                     
                  },
                  "inputs":[
                     "/var/log/pods/kube-system_pdcsi-node-vmxbk_8194ece2-46dd-495e-9220-3a6b88fa4d61/gce-pd-driver/0.log"
                  ],
                  "messages":[
                     "1 files tailed out of 1 files matching"
                  ],
                  "recent_avg_latency":0,
                  "recent_peak_latency":0,
                  "status":"OK",
                  "type":"file"
               }
            ]
         },
         {
            "name":"kube-system/l7-default-backend-6dc845c45d-xlnmh/default-http-backend",
            "sources":[
               {
                  "all_time_avg_latency":1365,
                  "all_time_peak_latency":5461,
                  "bytes_read":613,
                  "configuration":{
                     "Identifier":"0f23fbf70ab6cb8063cacb65bf7c7472a6e4062838764cac256439070942f161",
                     "Path":"/var/log/pods/kube-system_l7-default-backend-6dc845c45d-xlnmh_85840891-57e7-4fd4-8c1d-9a7ec5227614/default-http-backend/*.log",
                     "Service":"ingress-gce-404-server-with-metrics",
                     "Source":"ingress-gce-404-server-with-metrics"
                  },
                  "info":{
                     
                  },
                  "inputs":[
                     "/var/log/pods/kube-system_l7-default-backend-6dc845c45d-xlnmh_85840891-57e7-4fd4-8c1d-9a7ec5227614/default-http-backend/0.log"
                  ],
                  "messages":[
                     "1 files tailed out of 1 files matching"
                  ],
                  "recent_avg_latency":1365,
                  "recent_peak_latency":5461,
                  "status":"OK",
                  "type":"file"
               }
            ]
         }
      ],
      "is_running":true,
      "metrics":{
         "BytesSent":18474997,
         "EncodedBytesSent":18474997,
         "LogsProcessed":10438,
         "LogsSent":10438
      },
      "use_http":false,
      "warnings":[
         
      ]
   },
   "metadata":{
      "agent-flavor":"agent",
      "container-meta":{
         "cri_name":"containerd",
         "cri_version":"1.6.6",
         "docker_swarm":"inactive",
         "docker_version":"20.10.12",
         "kubelet_version":"v1.24.6-gke.1500"
      },
      "host-tags":{
         "google cloud platform":[
            "zone:asia-northeast1-a",
            "internal-hostname:gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
            "instance-id:90825865558996083",
            "project:datadog-sandbox",
            "numeric_project_id:958371799887",
            "cluster-name:dd-sandbox",
            "cluster-uid:3d6b7737edf6489fb1927577e24e8b0e314e6826aa3e47fa9b2eae419f261013",
            "cluster-location:asia-northeast1"
         ],
         "system":[
            "cluster_name:dd-sandbox",
            "kube_cluster_name:dd-sandbox"
         ]
      },
      "install-method":{
         "installer_version":"datadog-3.6.4",
         "tool":"helm",
         "tool_version":"Helm"
      },
      "logs":{
         "auto_multi_line_detection_enabled":false,
         "transport":"TCP"
      },
      "meta":{
         "cluster-name":"dd-sandbox",
         "ec2-hostname":"",
         "host_aliases":[
            "gke-dd-sandbox-bits-8943422b-5wpg-dd-sandbox",
            "gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
            "gke-dd-sandbox-bits-8943422b-5wpg.datadog-sandbox"
         ],
         "hostname":"gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
         "instance-id":"",
         "socket-fqdn":"dd-datadog-c4kcx",
         "socket-hostname":"dd-datadog-c4kcx",
         "timezones":[
            "GMT"
         ]
      },
      "network":null,
      "os":"linux",
      "otlp":{
         "enabled":false
      },
      "proxy-info":{
         "no-proxy-nonexact-match":false,
         "no-proxy-nonexact-match-explicitly-set":false,
         "proxy-behavior-changed":false
      },
      "python":"3.8.14 (default, Dec  9 2022, 10:01:06) [GCC 4.9.2]",
      "systemStats":{
         "cpuCores":1,
         "fbsdV":[
            "",
            "",
            ""
         ],
         "macV":[
            "",
            "",
            ""
         ],
         "machine":"amd64",
         "nixV":[
            "cos",
            "97",
            ""
         ],
         "platform":"linux",
         "processor":"Intel(R) Xeon(R) CPU @ 2.20GHz",
         "pythonV":"3.8.14",
         "winV":[
            "",
            "",
            ""
         ]
      }
   },
   "ntpOffset":0.000035142,
   "otlp":{
      "otlpCollectorStatus":"Not running",
      "otlpCollectorStatusErr":"",
      "otlpStatus":false
   },
   "pid":12136,
   "processAgentStatus":{
      "core":{
         "build_arch":"amd64",
         "config":{
            "log_level":"INFO"
         },
         "go_version":"go1.18.8",
         "metadata":{
            "agent-flavor":"agent",
            "container-meta":{
               "cri_name":"containerd",
               "cri_version":"1.6.6",
               "docker_swarm":"inactive",
               "docker_version":"20.10.12",
               "kubelet_version":"v1.24.6-gke.1500"
            },
            "host-tags":{
               "google cloud platform":[
                  "zone:asia-northeast1-a",
                  "internal-hostname:gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
                  "instance-id:90825865558996083",
                  "project:datadog-sandbox",
                  "numeric_project_id:958371799887",
                  "cluster-name:dd-sandbox",
                  "cluster-uid:3d6b7737edf6489fb1927577e24e8b0e314e6826aa3e47fa9b2eae419f261013",
                  "cluster-location:asia-northeast1"
               ],
               "system":[
                  "cluster_name:dd-sandbox",
                  "kube_cluster_name:dd-sandbox"
               ]
            },
            "install-method":{
               "installer_version":"docker",
               "tool":"docker",
               "tool_version":"docker"
            },
            "logs":{
               "auto_multi_line_detection_enabled":false,
               "transport":""
            },
            "meta":{
               "cluster-name":"dd-sandbox",
               "ec2-hostname":"",
               "host_aliases":[
                  "gke-dd-sandbox-bits-8943422b-5wpg-dd-sandbox",
                  "gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
                  "gke-dd-sandbox-bits-8943422b-5wpg.datadog-sandbox"
               ],
               "hostname":"gke-dd-sandbox-bits-8943422b-5wpg.c.datadog-sandbox.internal",
               "instance-id":"",
               "socket-fqdn":"dd-datadog-c4kcx",
               "socket-hostname":"dd-datadog-c4kcx",
               "timezones":[
                  "GMT"
               ]
            },
            "network":null,
            "os":"linux",
            "otlp":{
               "enabled":false
            },
            "proxy-info":{
               "no-proxy-nonexact-match":false,
               "no-proxy-nonexact-match-explicitly-set":false,
               "proxy-behavior-changed":false
            },
            "python":"n/a",
            "systemStats":{
               "cpuCores":1,
               "fbsdV":[
                  "",
                  "",
                  ""
               ],
               "macV":[
                  "",
                  "",
                  ""
               ],
               "machine":"amd64",
               "nixV":[
                  "cos",
                  "97",
                  ""
               ],
               "platform":"linux",
               "processor":"Intel(R) Xeon(R) CPU @ 2.20GHz",
               "pythonV":"n/a",
               "winV":[
                  "",
                  "",
                  ""
               ]
            }
         },
         "version":"x.y.z"
      },
      "date":1671576721802280200,
      "expvars":{
         "connections_queue_bytes":0,
         "connections_queue_size":0,
         "container_count":25,
         "container_id":"",
         "docker_socket":"",
         "drop_check_payloads":[
            
         ],
         "enabled_checks":[
            "container",
            "rtcontainer",
            "pod"
         ],
         "endpoints":{
            "https://process.datadoghq.com":[
               "841ae"
            ]
         },
         "event_queue_bytes":0,
         "event_queue_size":0,
         "last_collect_time":"2022-12-20 22:51:56",
         "log_file":"",
         "memstats":{
            "alloc":35295544
         },
         "pid":12223,
         "pod_queue_bytes":0,
         "pod_queue_size":0,
         "process_count":0,
         "process_queue_bytes":0,
         "process_queue_size":0,
         "proxy_url":"",
         "rtprocess_queue_bytes":0,
         "rtprocess_queue_size":0,
         "uptime":12633,
         "uptime_nano":1671564088069916200,
         "version":{
            "BuildDate":"",
            "GitBranch":"",
            "GitCommit":"",
            "GoVersion":"",
            "Version":""
         }
      }
   },
   "pyLoaderStats":{
      "ConfigureErrors":{
         "postgres (13.1.0)":[
            "could not invoke 'postgres' python check constructor. New constructor API returned:\nTraceback (most recent call last):\n  File \"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/postgres.py\", line 62, in __init__\n    self._config = PostgresConfig(self.instance)\n  File \"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/postgres/config.py\", line 35, in __init__\n    raise ConfigurationError('Please specify a user to connect to Postgres.')\ndatadog_checks.base.errors.ConfigurationError: Please specify a user to connect to Postgres.\nDeprecated constructor API returned:\n__init__() got an unexpected keyword argument 'agentConfig'"
         ]
      },
      "Py3Warnings":{
         
      }
   },
   "pythonInit":{
      "Errors":[
         
      ]
   },
   "python_version":"3.8.14",
   "runnerStats":{
      "Checks":{
         "cilium":{
            "cilium:bac99095d52d45c":{
               "AverageExecutionTime":8,
               "CheckConfigSource":"file:/etc/datadog-agent/conf.d/cilium.d/auto_conf.yaml",
               "CheckID":"cilium:bac99095d52d45c",
               "CheckName":"cilium",
               "CheckVersion":"2.3.0",
               "EventPlatformEvents":{
                  
               },
               "Events":0,
               "ExecutionTimes":[
                  9,
                  9,
                  9,
                  8,
                  10,
                  11,
                  8,
                  8,
                  8,
                  9,
                  8,
                  8,
                  10,
                  8,
                  11,
                  8,
                  8,
                  8,
                  9,
                  9,
                  10,
                  10,
                  8,
                  8,
                  10,
                  9,
                  9,
                  9,
                  10,
                  8,
                  9,
                  8
               ],
               "HistogramBuckets":0,
               "LastError":"[{\"message\": \"HTTPConnectionPool(host='10.146.15.207', port=9090): Max retries exceeded with url: /metrics (Caused by NewConnectionError('\u003curllib3.connection.HTTPConnection object at 0x7f20296ba430\u003e: Failed to establish a new connection: [Errno 111] Connection refused'))\", \"traceback\": \"Traceback (most recent call last):\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py\\\", line 174, in _new_conn\\n    conn = connection.create_connection(\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/util/connection.py\\\", line 95, in create_connection\\n    raise err\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/util/connection.py\\\", line 85, in create_connection\\n    sock.connect(sa)\\nConnectionRefusedError: [Errno 111] Connection refused\\n\\nDuring handling of the above exception, another exception occurred:\\n\\nTraceback (most recent call last):\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connectionpool.py\\\", line 703, in urlopen\\n    httplib_response = self._make_request(\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connectionpool.py\\\", line 398, in _make_request\\n    conn.request(method, url, **httplib_request_kw)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py\\\", line 239, in request\\n    super(HTTPConnection, self).request(method, url, body=body, headers=headers)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/http/client.py\\\", line 1256, in request\\n    self._send_request(method, url, body, headers, encode_chunked)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/http/client.py\\\", line 1302, in _send_request\\n    self.endheaders(body, encode_chunked=encode_chunked)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/http/client.py\\\", line 1251, in endheaders\\n    self._send_output(message_body, encode_chunked=encode_chunked)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/http/client.py\\\", line 1011, in _send_output\\n    self.send(msg)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/http/client.py\\\", line 951, in send\\n    self.connect()\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py\\\", line 205, in connect\\n    conn = self._new_conn()\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connection.py\\\", line 186, in _new_conn\\n    raise NewConnectionError(\\nurllib3.exceptions.NewConnectionError: \u003curllib3.connection.HTTPConnection object at 0x7f20296ba430\u003e: Failed to establish a new connection: [Errno 111] Connection refused\\n\\nDuring handling of the above exception, another exception occurred:\\n\\nTraceback (most recent call last):\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/adapters.py\\\", line 489, in send\\n    resp = conn.urlopen(\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/connectionpool.py\\\", line 787, in urlopen\\n    retries = retries.increment(\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/urllib3/util/retry.py\\\", line 592, in increment\\n    raise MaxRetryError(_pool, url, error or ResponseError(cause))\\nurllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='10.146.15.207', port=9090): Max retries exceeded with url: /metrics (Caused by NewConnectionError('\u003curllib3.connection.HTTPConnection object at 0x7f20296ba430\u003e: Failed to establish a new connection: [Errno 111] Connection refused'))\\n\\nDuring handling of the above exception, another exception occurred:\\n\\nTraceback (most recent call last):\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/base.py\\\", line 1122, in run\\n    self.check(instance)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/base_check.py\\\", line 142, in check\\n    self.process(scraper_config)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py\\\", line 573, in process\\n    for metric in self.scrape_metrics(scraper_config):\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py\\\", line 500, in scrape_metrics\\n    response = self.poll(scraper_config)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py\\\", line 837, in poll\\n    response = self.send_request(endpoint, scraper_config, headers)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/checks/openmetrics/mixins.py\\\", line 863, in send_request\\n    return http_handler.get(endpoint, stream=True, **kwargs)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/utils/http.py\\\", line 356, in get\\n    return self._request('get', url, options)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/utils/http.py\\\", line 420, in _request\\n    response = self.make_request_aia_chasing(request_method, method, url, new_options, persist)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/datadog_checks/base/utils/http.py\\\", line 426, in make_request_aia_chasing\\n    response = request_method(url, **new_options)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/api.py\\\", line 73, in get\\n    return request(\\\"get\\\", url, params=params, **kwargs)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/api.py\\\", line 59, in request\\n    return session.request(method=method, url=url, **kwargs)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/sessions.py\\\", line 587, in request\\n    resp = self.send(prep, **send_kwargs)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/sessions.py\\\", line 701, in send\\n    r = adapter.send(request, **kwargs)\\n  File \\\"/opt/datadog-agent/embedded/lib/python3.8/site-packages/requests/adapters.py\\\", line 565, in send\\n    raise ConnectionError(e, request=request)\\nrequests.exceptions.ConnectionError: HTTPConnectionPool(host='10.146.15.207', port=9090): Max retries exceeded with url: /metrics (Caused by NewConnectionError('\u003curllib3.connection.HTTPConnection object at 0x7f20296ba430\u003e: Failed to establish a new connection: [Errno 111] Connection refused'))\\n\"}]",
               "LastExecutionTime":9,
               "LastSuccessDate":0,
               "LastWarnings":[
                  
               ],
               "MetricSamples":0,
               "ServiceChecks":1,
               "TotalErrors":842,
               "TotalEventPlatformEvents":{
                  
               },
               "TotalEvents":0,
               "TotalHistogramBuckets":0,
               "TotalMetricSamples":0,
               "TotalRuns":842,
               "TotalServiceChecks":842,
               "TotalWarnings":0,
               "UpdateTimestamp":1671576714
            }
         },
         "datadog_cluster_agent":{
            "datadog_cluster_agent:4b0f56c49d48c92e":{
               "AverageExecutionTime":29,
               "CheckConfigSource":"file:/etc/datadog-agent/conf.d/datadog_cluster_agent.d/auto_conf.yaml",
               "CheckID":"datadog_cluster_agent:4b0f56c49d48c92e",
               "CheckName":"datadog_cluster_agent",
               "CheckVersion":"2.4.0",
               "EventPlatformEvents":{
                  
               },
               "Events":0,
               "ExecutionTimes":[
                  32,
                  27,
                  33,
                  29,
                  28,
                  27,
                  28,
                  34,
                  28,
                  28,
                  29,
                  35,
                  30,
                  31,
                  26,
                  28,
                  31,
                  29,
                  28,
                  27,
                  34,
                  27,
                  30,
                  28,
                  32,
                  31,
                  28,
                  29,
                  29,
                  33,
                  33,
                  27
               ],
               "HistogramBuckets":0,
               "LastError":"",
               "LastExecutionTime":28,
               "LastSuccessDate":1671576721,
               "LastWarnings":[
                  
               ],
               "MetricSamples":125,
               "ServiceChecks":1,
               "TotalErrors":0,
               "TotalEventPlatformEvents":{
                  
               },
               "TotalEvents":0,
               "TotalHistogramBuckets":0,
               "TotalMetricSamples":104832,
               "TotalRuns":842,
               "TotalServiceChecks":842,
               "TotalWarnings":0,
               "UpdateTimestamp":1671576721
            },
            "datadog_cluster_agent:79dc7329a0398f09":{
               "AverageExecutionTime":25,
               "CheckConfigSource":"file:/etc/datadog-agent/conf.d/datadog_cluster_agent.d/auto_conf.yaml",
               "CheckID":"datadog_cluster_agent:79dc7329a0398f09",
               "CheckName":"datadog_cluster_agent",
               "CheckVersion":"2.4.0",
               "EventPlatformEvents":{
                  
               },
               "Events":0,
               "ExecutionTimes":[
                  26,
                  30,
                  33,
                  26,
                  26,
                  19,
                  24,
                  32,
                  20,
                  23,
                  23,
                  23,
                  27,
                  25,
                  28,
                  20,
                  23,
                  23,
                  25,
                  26,
                  26,
                  20,
                  26,
                  30,
                  27,
                  24,
                  23,
                  26,
                  27,
                  24,
                  28,
                  21
               ],
               "HistogramBuckets":0,
               "LastError":"",
               "LastExecutionTime":19,
               "LastSuccessDate":1671576719,
               "LastWarnings":[
                  
               ],
               "MetricSamples":61,
               "ServiceChecks":1,
               "TotalErrors":0,
               "TotalEventPlatformEvents":{
                  
               },
               "TotalEvents":0,
               "TotalHistogramBuckets":0,
               "TotalMetricSamples":50672,
               "TotalRuns":838,
               "TotalServiceChecks":838,
               "TotalWarnings":0,
               "UpdateTimestamp":1671576719
            }
         },
         "network":{
            "network:d884b5186b651429":{
               "AverageExecutionTime":6,
               "CheckConfigSource":"file:/etc/datadog-agent/conf.d/network.d/conf.yaml.default",
               "CheckID":"network:d884b5186b651429",
               "CheckName":"network",
               "CheckVersion":"2.9.2",
               "EventPlatformEvents":{
                  
               },
               "Events":0,
               "ExecutionTimes":[
                  7,
                  5,
                  6,
                  5,
                  5,
                  5,
                  7,
                  5,
                  6,
                  6,
                  6,
                  6,
                  6,
                  7,
                  5,
                  5,
                  6,
                  6,
                  5,
                  5,
                  6,
                  8,
                  7,
                  7,
                  8,
                  5,
                  7,
                  5,
                  6,
                  8,
                  7,
                  5
               ],
               "HistogramBuckets":0,
               "LastError":"",
               "LastExecutionTime":6,
               "LastSuccessDate":1671576708,
               "LastWarnings":[
                  
               ],
               "MetricSamples":174,
               "ServiceChecks":0,
               "TotalErrors":0,
               "TotalEventPlatformEvents":{
                  
               },
               "TotalEvents":0,
               "TotalHistogramBuckets":0,
               "TotalMetricSamples":146334,
               "TotalRuns":841,
               "TotalServiceChecks":0,
               "TotalWarnings":0,
               "UpdateTimestamp":1671576708
            }
         }
      },
      "Errors":1685,
      "Running":{
         
      },
      "RunningChecks":0,
      "Runs":16635,
      "Workers":{
         "Count":4,
         "Instances":{
            "worker_1":{
               "Utilization":0.02
            },
            "worker_2":{
               "Utilization":0.02
            },
            "worker_3":{
               "Utilization":0.01
            },
            "worker_4":{
               "Utilization":0.01
            }
         }
      }
   },
   "snmpTrapsStats":{
      "metrics":{
         "Packets":0,
         "PacketsAuthErrors":0
      }
   },
   "time_nano":1671576721796997600,
   "version":"x.y.z"
}`
