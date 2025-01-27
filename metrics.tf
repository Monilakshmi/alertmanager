
locals {
  issuer_no_scheme = replace(data.aws_eks_cluster.current.identity[0].oidc[0].issuer, "https://", "")

}

resource "helm_release" "prometheus" {
  name = "prometheus"
  # chart = "${path.module}/../../charts/observability-k8s/prometheus"
  # depends_on = [helm_release.kube_prometheus_stack]
  # lint             = true
  namespace        = local.observability_ns
  create_namespace = true
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "prometheus"
values = [<<EOF
serverFiles:
  alerting_rules.yml: 
    groups:
# INSTANCE RULE : On High CPU consumption more than 98%
      - name: HighCPULoad
        rules:
          - alert: HighCPULoad
            expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 98
            for: 5m
            labels:
              severity: critical
              ruletype: instancerules
            annotations:
              summary: "High CPU load on instance"
              description: "CPU load is > 98%\n for 10 minutes Current CPU Load"

# INSTANCE RULE : On High memory consumption more than 98%
      - name: MemoryMaxConsumption
        rules:
          - alert: MemoryMaxConsumption
            expr: (node_memory_MemFree_bytes + node_memory_Cached_bytes + node_memory_Buffers_bytes) / node_memory_MemTotal_bytes * 100 < 2
            for: 10m
            labels:
              severity: critical
              ruletype: instancerules
            annotations:
              summary: "Memory consumption is more than 98% for last 10 minutes in ({{ $labels.instance }})"
              description: "Node memory is filling up (< 1% left)\n  VALUE = {{ $value }}\n  LABELS: {{ $labels.instance }}"

# CONTAINER RULES : Container killed before a hour not coming back up
      - name: Container_Down
        rules:
          - alert: Container_Down
            expr: time() - container_last_seen > 60
            for: 10m
            labels:
              severity: warning
              ruletype: containerrules
            annotations:
              summary: "Container killed instance ({{ $labels.instance }})"
              description: "A container has disappeared\n  VALUE = {{ $value }}\n  LABELS: {{ $labels }}"

# CONTAINER RULES : Container restarted for more than 10 times in last 1 hour
      - name: Critical_Container_Restart
        rules:
          - alert: Critical_Container_Restart
            expr: rate(kube_pod_container_status_restarts_total[1h]) * 3600 > 10
            for: 60m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} restarted"
              description: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} restarted more than 10 times in last 1 hour\n  VALUE = {{ $value }}\n  LABELS: {{ $labels }}"

# CONTAINER RULES : Job is in creating status for more than 1 hour
      - name: job_Container_Creating
        rules:
          - alert: job_Container_Creating
            # expr: kube_pod_container_status_waiting_reason{reason="ContainerCreating", pod=~"filemaf.*"} == 1
            expr: (kube_pod_container_status_waiting_reason{reason="ContainerCreating"}) * on(pod) group_right(labels)(kube_pod_labels{label_maf_jobid!=""})
            for: 60m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "File processing Pod {{$labels.pod}} is in ContainerCreating"
              description: "Pod {{$labels.pod}} is in ContainerCreating status for more than 60 minutes.  VALUE = {{ $value }}"

# CONTAINER RULES :Job is not completed on time
      - name: Jobs not completed on time
        rules:
          - alert: Jobs not completed on time
            expr: (kube_pod_status_phase{phase="Running"}) * on(pod) group_right(labels)(kube_pod_labels{label_maf_jobid!=""}) > 0
            for: 360m
            labels:
              ruletype: containerrules
            annotations:
              summary: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} running for more than 6 hour"
              description: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in running state for more than 6 hours\n  VALUE = {{ $value }}\n  LABELS: {{ $labels }}"

# CONTAINER RULES :Jobs  pending for an hour
      - name: Jobs in PENDING status
        rules:
          - alert: Jobs in PENDING status
            expr: (kube_pod_status_phase{phase="Pending"}) * on(pod) group_right(labels)(kube_pod_labels{label_maf_jobid!=""}) > 0
            for: 360m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in pending state"
              description: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in pending state for more than an hour\n  LABELS: {{ $labels }}"

# CONTAINER RULES :Jobs failed for 2hours
      - name: Jobs in Failed status
        rules:
          - alert: Jobs in Failed status
            expr: (kube_pod_status_phase{phase="Failed"}) * on(pod) group_right(labels)(kube_pod_labels{label_maf_jobid!=""}) > 0
            for: 120m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in failed state"
              description: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in failed state for than two hours \n  VALUE = {{ $value }}\n  LABELS: {{ $labels }}"

# CONTAINER RULES:Jobs failed with evicted reason for 2hours
      - name: Jobs in evicted status
        rules:
          - alert: Jobs in evicted status
            expr: kube_pod_status_reason{reason="Evicted"} > 0
            for: 180m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in evicted state for more than 3 hours"
              description: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} is in evicted state for than three hours \n  VALUE = {{ $value }}\n  LABELS: {{ $labels }}"

# pod in unknowncontainer status for 3 hours
      - name: Container_Status_Unknown
        rules:
          - alert: Container_Status_Unknown
            expr: kube_pod_info{status="Unknown"} == 1 and kube_pod_container_status_restarts_total > 0
            for: 180m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "Pod {{$labels.pod}} in namespace {{$labels.namespace}} has container(s) in unknowncontainerstatus for more than 3 hours"
              description: "pod {{$labels.pod}} in namespace {{$labels.namespace}} in a unknowncontainerstatus  for more than three hours \n  VALUE = {{ $value }}\n  LABELS: {{ $labels }}"

# pod is failing with ImagePullBackOff error 
      - name: ImagePullBackOff
        rules:
          - alert: ImagePullBackOff
            expr: kube_pod_container_status_waiting_reason{reason="ImagePullBackOff"} > 0
            for: 30m
            labels:
              severity: critical
              ruletype: containerrules
            annotations:
              summary: "Container {{ $labels.container }} in pod {{ $labels.pod }} in namespace {{$labels.namespace}} is in ImagePullBackOff state for 30 minutes."
        
# Blackbox exporter endpoints
      - name: HTTP_Endpoint_Down
        rules:
          - alert: HTTP_Endpoint_Down
            expr: probe_success == 0
            for: 10s
            labels:
              severity: critical
            annotations:
              summary: "HTTP Endpoint {{ $labels.instance }} is down"
              description: "HTTP Endpoint {{ $labels.instance }} is not reachable. Check the respective service or deployment"

alertmanager:
  config:
    route:
      group_by: ['alertname']
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 1h
      receiver: 'alert-sns'
      routes:
        - matchers:
            - 'ruletype=instancerules'
          receiver: 'instance-sns'
        - matchers:
            - 'ruletype=containerrules'
          receiver: 'container-sns'
    receivers:
      - name: 'alert-sns'
        sns_configs:
          - api_url: 'https://sns.us-west-2.amazonaws.com'
            topic_arn: 'arn:aws:sns:us-west-2:737281747633:Alert-manager-test'
            sigv4:
              region: 'us-west-2'
            subject: 'Alerts'
            message: |
              {{ range .Alerts }}
              Alerts Resolved:
              Labels:
              {{ range .Labels.SortedPairs }}- {{ .Name }} = {{ .Value }}{{ end }}
              Annotations:
              {{ range .Annotations.SortedPairs }}- {{ .Name }} = {{ .Value }}{{ end }}
              Source: {{ .GeneratorURL }}
              {{ end }}
            attributes:
              severity: SEV4

      - name: 'instance-sns'
        sns_configs:
          - api_url: 'https://sns.us-west-2.amazonaws.com'
            topic_arn: 'arn:aws:sns:us-west-2:737281747633:Alert-manager-test'
            sigv4:
              region: 'us-west-2'
            subject: 'Instance Alerts'
            message: |
              {{ range .Alerts }}
              Alerts Resolved:
              Labels:
              {{ range .Labels.SortedPairs }}- {{ .Name }} = {{ .Value }}{{ end }}
              Annotations:
              {{ range .Annotations.SortedPairs }}- {{ .Name }} = {{ .Value }}{{ end }}
              Source: {{ .GeneratorURL }}
              {{ end }}
            attributes:
              severity: SEV2

      - name: 'container-sns'
        sns_configs:
          - api_url: 'https://sns.us-west-2.amazonaws.com'
            topic_arn: 'arn:aws:sns:us-west-2:737281747633:Alert-manager-test'
            sigv4:
              region: 'us-west-2'
            subject: 'Container Alerts'
            message: |
              {{ range .Alerts }}
              Alerts Resolved:
              Labels:
              {{ range .Labels.SortedPairs }}- {{ .Name }} = {{ .Value }}{{ end }}
              Annotations:
              {{ range .Annotations.SortedPairs }}- {{ .Name }} = {{ .Value }}{{ end }}
              Source: {{ .GeneratorURL }}
              {{ end }}
            attributes:
              severity: SEV2
EOF
  ]
}             


resource "helm_release" "keda" {
  count            = var.enable_keda ? 1 : 0
  name             = "keda"
  repository       = "https://kedacore.github.io/charts"
  chart            = "keda"
  namespace        = "keda"
  create_namespace = true
}

