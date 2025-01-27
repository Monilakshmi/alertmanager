locals {
  issuer_no_scheme = replace(data.aws_eks_cluster.current.identity[0].oidc[0].issuer, "https://", "")

  prometheus_dns_subdomain = "prometheus${local.dns_suffix}"
  prometheus_lb_host       = "${local.prometheus_dns_subdomain}.${var.domain}"

  grafana_dns_subdomain = "maf-grafana${local.dns_suffix}"
  grafana_lb_host       = "${local.grafana_dns_subdomain}.${var.domain}"
  grafana_admin_user    = "admin"
}

// Prometheus + Alertmanager
resource "aws_prometheus_workspace" "amp" {
  count = var.enable_prometheus ? 1 : 0
  alias = "${var.app_name}-${var.env}-amp"
}

data "aws_iam_policy_document" "amp_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"
      identifiers = [
        #         "arn:aws:iam::${local.aws_account}:oidc-provider/oidc.eks.${local.aws_region}.amazonaws.com/id/${local.cluster_id}",
        "arn:aws:iam::${local.aws_account}:oidc-provider/${local.issuer_no_scheme}"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.issuer_no_scheme}:sub"
      values   = ["system:serviceaccount:${local.ns}:svc-maf-monitoring"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.issuer_no_scheme}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "amp" {
  count = var.enable_prometheus ? 1 : 0

  name                 = "CustomerManaged_PrometheusRole-${var.env}"
  permissions_boundary = var.iam_permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.amp_assume_role.json
}

resource "aws_iam_role_policy_attachment" "amp" {
  count = var.enable_prometheus ? 1 : 0

  role       = aws_iam_role.amp[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonPrometheusFullAccess"
}

resource "helm_release" "kube_prometheus_stack" {
  count      = var.enable_prometheus ? 1 : 0
  depends_on = [helm_release.maf_infra]

  name       = "kube-prometheus-stack"
  namespace  = local.ns
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "67.4.0"

  values = [<<EOF
prometheus:
  prometheusSpec:
    serviceMonitorNamespaceSelector: {}
    serviceMonitorSelector: {}
    scrapeConfigNamespaceSelector: {}
    scrapeConfigSelector: {}
    ruleSelectorNilUsesHelmValues: false
    serviceMonitorSelectorNilUsesHelmValues: false
    podMonitorSelectorNilUsesHelmValues: false
    probeSelectorNilUsesHelmValues: false
    scrapeConfigSelectorNilUsesHelmValues: false
    nodeSelector:
      ${var.node_selector_label}: "${var.core_node_selector}"
    remoteWrite:
      - sigv4:
          region: ${local.aws_region}
        url: ${aws_prometheus_workspace.amp[0].prometheus_endpoint}api/v1/remote_write
        writeRelabelConfigs:
          - action: keep
            regex: kube_pod_created|kube_pod_start_time|kube_pod_completion_time|container_cpu_usage_seconds_total|container_memory_working_set_bytes|node_memory_MemFree_bytes|node_memory_Cached_bytes|node_memory_MemTotal_bytes|node_memory_Buffers_bytes|node_cpu_seconds_total|node_filesystem_free_bytes|node_filesystem_size_bytes|kube_pod_container_status_restarts_total|kube_pod_container_status_waiting_reason|kube_pod_container_status_running|kube_pod_container_status_terminated_reason|kube_pod_container_status_last_terminated_reason|container_last_seen|container_memory_usage_bytes|container_running|container_terminated_reason|container_last_terminated_reason|calls_total|latency_bucket|latency_sum|latency_count|kube_pod_labels|kube_pod_status_phase|kube_pod_status_reason
            sourceLabels:
              - __name__
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: "${aws_iam_role.amp[0].arn}"
    name: svc-maf-monitoring

  ingress:
    enabled: true
    ingressClassName: ${local.internal_ingress_class_name}
    annotations:
      alb.ingress.kubernetes.io/target-type: ip
    hosts:
      - ${local.prometheus_lb_host}
    pathType: Prefix

kube-state-metrics:
  nodeSelector:
    ${var.node_selector_label}: "${var.core_node_selector}"
  metricLabelsAllowlist: 
        - pods=[*]
        - jobs=[*]

alertmanager:
  enabled: true
  alertmanagerSpec:
    nodeSelector:
      ${var.node_selector_label}: "${var.core_node_selector}"

prometheusOperator:
  namespaces:
    releaseNamespace: true
  enabled: true
  nodeSelector:
    ${var.node_selector_label}: "${var.core_node_selector}"

grafana:
  enabled: true
  nodeSelector:
    ${var.node_selector_label}: "${var.core_node_selector}"
  annotations:
    secret.reloader.stakater.com/reload: "grafana-creds"

  adminPassword: ""
  admin:
    existingSecret: grafana-creds  # see helm chart for this secret
    userKey: ADMIN_USERNAME
    passwordKey: ADMIN_PASSWORD

  envFromSecret: grafana-creds
  grafana.ini:
    server:
      root_url: https://${local.grafana_lb_host}/
    %{~if var.grafana_azure_config != null}
    auth.azuread:
      enabled: true
      name: Azure AD
      allow_sign_up: true
      auto_login: false
      client_id: ${var.grafana_azure_config.client_id}
      client_secret: $__env{AZUREAD_CLIENT_SECRET}
      scopes: openid email profile
      auth_url: https://login.microsoftonline.com/${var.grafana_azure_config.tenant_id}/oauth2/v2.0/authorize
      token_url: https://login.microsoftonline.com/${var.grafana_azure_config.tenant_id}/oauth2/v2.0/token
      allowed_organizations: ${var.grafana_azure_config.tenant_id}
      role_attribute_strict: false
      allow_assign_grafana_admin: true
      skip_org_role_sync: false
      use_pkce: true
    %{~endif}
  podLabels:
    dashboards: grafana

  ingress:
    enabled: true
    ingressClassName: ${local.external_ingress_class_name}
    annotations:
      alb.ingress.kubernetes.io/target-type: ip
    hosts:
      - ${local.grafana_lb_host}
    pathType: Prefix
EOF
  ]

  timeout = 600
}

module "prometheus_record" {
  count = var.enable_prometheus ? 1 : 0

  source           = "../kube_dns_record"
  route53_zone_id  = var.route53_zone_id
  vinyldns_zone_id = var.vinyldns_zone_id
  domain           = var.domain
  subdomain        = local.prometheus_dns_subdomain

  helm_release_output_hash     = md5(jsonencode(helm_release.kube_prometheus_stack[0]))
  kubernetes_ingress_name      = "kube-prometheus-stack-prometheus"
  kubernetes_ingress_namespace = local.ns
  maf_kubeconfig_content       = local.maf_kubeconfig_content
}

module "grafana_record" {
  count  = var.enable_prometheus ? 1 : 0
  source = "../kube_dns_record"

  route53_zone_id  = var.route53_zone_id
  vinyldns_zone_id = var.vinyldns_zone_id
  domain           = var.domain
  subdomain        = local.grafana_dns_subdomain

  helm_release_output_hash     = md5(jsonencode(helm_release.kube_prometheus_stack[0]))
  kubernetes_ingress_name      = "kube-prometheus-stack-grafana"
  kubernetes_ingress_namespace = local.ns
  maf_kubeconfig_content       = local.maf_kubeconfig_content
}


resource "helm_release" "prometheus-blackbox-exporter" {
  count      = var.enable_prometheus ? 1 : 0
  depends_on = [helm_release.kube_prometheus_stack]

  name             = "prometheus-blackbox-exporter"
  namespace        = local.ns
  create_namespace = true
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "prometheus-blackbox-exporter"
  version          = "8.4.0"

  values = [<<EOF
serviceMonitor:
  enabled: true
nodeSelector:
  ${var.node_selector_label}: "${var.core_node_selector}"
EOF
  ]

  timeout = 600
}

// Alerts
resource "aws_sns_topic" "amp" {
  count = var.enable_prometheus ? 1 : 0
  name  = "${var.app_name}-${var.region_initials}-${var.env}-amp-notifications"
}

data "aws_iam_policy_document" "amp_sns_topic" {
  count = var.enable_prometheus ? 1 : 0

  policy_id = "__default_policy_ID"
  statement {
    sid = "__default_statement_ID"

    effect = "Allow"
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]
    resources = [aws_sns_topic.amp[0].arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOwner"
      values   = [local.aws_account]
    }
  }

  statement {
    sid = "Allow_Publish_Alarms"

    effect = "Allow"
    actions = [
      "sns:Publish",
      "sns:GetTopicAttributes",
    ]
    resources = [aws_sns_topic.amp[0].arn]

    principals {
      type        = "Service"
      identifiers = ["aps.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_prometheus_workspace.amp[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.aws_account]
    }
  }
}

resource "aws_sns_topic_policy" "amp" {
  count  = var.enable_prometheus ? 1 : 0
  arn    = aws_sns_topic.amp[0].arn
  policy = data.aws_iam_policy_document.amp_sns_topic[0].json
}

resource "aws_prometheus_alert_manager_definition" "alerts" {
  count = var.enable_prometheus ? 1 : 0

  workspace_id = aws_prometheus_workspace.amp[0].id
  definition   = <<EOF
alertmanager_config: |
  route:
    group_by: ["alertname"]
    group_wait: 30s
    group_interval: 1h
    repeat_interval: 1h
    receiver: "default"
    routes:
    - match:
        "ruletype": "instancerules"
      receiver: "instancerules"
    - match:
        "ruletype": "containerrules"
      receiver: "containerrules"
  receivers:
    - name: 'default'
      sns_configs:
      - topic_arn: ${aws_sns_topic.amp[0].arn}
        subject: Alarm test for prometheus
        sigv4:
          region: ${local.aws_region}
        attributes:
          key: severity
          value: SEV4
    - name: 'instancerules'
      sns_configs:
      - topic_arn: ${aws_sns_topic.amp[0].arn}
        subject: Instance alerts from prometheus
        sigv4:
          region: ${local.aws_region}
        attributes:
          key: severity
          value: SEV2
    - name: 'containerrules'
      sns_configs:
      - topic_arn: ${aws_sns_topic.amp[0].arn}
        subject: Container alerts from prometheus
        sigv4:
          region: ${local.aws_region}
        attributes:
          key: severity
          value: SEV2
EOF
}

resource "aws_prometheus_rule_group_namespace" "rules" {
  count = var.enable_prometheus ? 1 : 0

  name         = "amp_eks_rule"
  workspace_id = aws_prometheus_workspace.amp[0].id
  data         = file("${path.module}/configs/amp_rules.yaml")
}

resource "aws_sns_topic_subscription" "amp" {
  for_each   = toset(var.enable_prometheus ? var.alert_emails : [])
  depends_on = [aws_prometheus_alert_manager_definition.alerts]

  topic_arn = aws_sns_topic.amp[0].arn
  protocol  = "email"
  endpoint  = each.value
}

// Grafana
resource "helm_release" "grafana_operator" {
  count = var.enable_prometheus ? 1 : 0

  name             = "grafana-operator"
  namespace        = local.ns
  create_namespace = true
  repository       = "oci://ghcr.io/grafana/helm-charts"
  chart            = "grafana-operator"
  version          = "v5.15.1"

  values = [<<EOF
installCRDs: true
nodeSelector:
  ${var.node_selector_label}: "${var.core_node_selector}"
EOF
  ]
}

data "archive_file" "metrics" {
  type        = "zip"
  source_dir  = "${path.module}/../../charts/observability-k8s/metrics"
  output_path = "/tmp/tf/metrics.zip"
}

resource "helm_release" "metrics_resources" {
  count      = var.enable_prometheus ? 1 : 0
  depends_on = [helm_release.kube_prometheus_stack, helm_release.grafana_operator]

  name             = "metrics-resources"
  namespace        = local.ns
  create_namespace = true
  chart            = "${path.module}/../../charts/observability-k8s/metrics"
  lint             = true

  values = [<<-YAML
hash: "${data.archive_file.metrics.output_sha}"
grafanaUrl: "http://kube-prometheus-stack-grafana.${local.ns}"
lb:
  grafanaHost: "${local.grafana_lb_host}"
  prometheusHost: "${local.prometheus_lb_host}"
YAML
  ]
}

// DataDog
data "archive_file" "maf_datadog" {
  type        = "zip"
  source_dir  = "${path.module}/../../charts/observability-k8s/maf-datadog"
  output_path = "/tmp/tf/maf-datadog.zip"
}

data "aws_secretsmanager_secret" "datadog" {
  count = var.datadog_secret_name != null ? 1 : 0
  name  = var.datadog_secret_name
}

data "aws_secretsmanager_secret_version" "datadog" {
  count     = var.datadog_secret_name != null ? 1 : 0
  secret_id = data.aws_secretsmanager_secret.datadog[0].id
}

resource "helm_release" "maf_datadog" {
  count = var.datadog_secret_name != null ? 1 : 0

  name             = "maf-datadog"
  namespace        = local.ns
  create_namespace = true
  chart            = "${path.module}/../../charts/observability-k8s/maf-datadog"
  lint             = true

  set {
    name  = "hash"
    value = data.archive_file.maf_datadog.output_sha
  }
  set {
    name  = "clusterName"
    value = var.eks_cluster_name
  }

  set_sensitive {
    name  = "secretApiKey"
    value = jsondecode(data.aws_secretsmanager_secret_version.datadog[0].secret_string)["api_key"]
  }
  set_sensitive {
    name  = "secretClusterAgentToken"
    value = jsondecode(data.aws_secretsmanager_secret_version.datadog[0].secret_string)["token"]
  }
}

///

resource "helm_release" "keda" {
  count = var.enable_prometheus ? 1 : 0

  name       = "keda"
  namespace  = "kube-system"
  repository = "https://kedacore.github.io/charts"
  chart      = "keda"
  version    = "2.16.1"

  values = [<<EOF
nodeSelector:
  ${var.node_selector_label}: "${var.core_node_selector}"
EOF
  ]
}
