Cert Secret Syncer
==================
This kubernetes controller synchronizes a certificate stored in a `kubernetes.io/tls` secret with infrastructure providers.

You might want this, for example, to synchronize certificates managed by `cert-manager` with `AWS Certificate Manager` so that the ALB attached to an ingress has the generated certificate to terminate TLS on the edge.

Cert Secret Syncer currently only supports Amazon Certificate Manager.


How To
------
The controller relies on permissions granted to a ServiceAccount through OIDC (Open ID Connect). If you install EKS with Terraform, you'll need to start with something like this...

```
module "cert_secret_syncer_irsa" {
  source                        = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version                       = "3.6.0"
  create_role                   = true
  role_name                     = "${var.cluster_name}_cert-secret-syncer-irsa"
  provider_url                  = replace(module.eks.cluster_oidc_issuer_url, "https://", "")
  role_policy_arns              = [aws_iam_policy.cert-secret-syncer_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:cert-secret-syncer:cert-secret-syncer"]
}

resource "aws_iam_policy" "cert-secret-syncer_policy" {
  name        = "${var.cluster_name}_cert-secret-syncer_policy"
  path        = "/"
  description = "Policy for aws load balancer controller"

  policy = jsonencode(
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                    "acm:ImportCertificate",
                    "acm:ListTagsForCertificate",
                    "acm:AddTagsToCertificate"
            ],
            "Resource": "*"
        }
    ]
  })
}

output "cert_secret_syncer_irsa_role_arn" {
  value = module.cert_secret_syncer_irsa.this_iam_role_arn
}
```

Then, grab the ARN from the Terraform outputs and annotate the `ServiceAccount` through the chart `values.yaml` file like this:

```
serviceAccount:
  # Specifies whether a service account should be created
  create: true
  # Annotations to add to the service account
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::807125168235:role/live-shinetribe_cert-secret-syncer-irsa
  # The name of the service account to use.
  # If not set and create is true, a name is generated using the fullname template
  name: ""
```

At that point, you are probably ready to apply the helm chart. First add the repo

```
helm repo add jxgh https://jenkins-x-charts.github.io/repo
```

Then you can install or upgrade using:

```
helm repo update
helm upgrade [RELEASE_NAME] jxgh/cert-secret-syncer --install
```

When you are ready, create a `Certificate` and `Ingress` like this...

```
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: merchie
  namespace: fg
spec:
  secretName: merchie-tls
  secretTemplate:
    annotations:
      "cert-secret-syncer/backend": "ACM"
      "cert-secret-syncer/ingress-labels": "app=merchie"
    labels:
      app: merchie
  duration: 2160h # 90d
  renewBefore: 360h # 15d
  isCA: false
  privateKey:
    algorithm: RSA
    encoding: PKCS1
    size: 2048
  dnsNames:
    - order.live.shinetribe.media
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: merchie
  namespace: fg
  labels:
    app: merchie
  annotations:
    kubernetes.io/ingress.class: alb
    # see https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.5/guide/ingress/annotations/#listen-ports
    alb.ingress.kubernetes.io/target-type: instance
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS": 443}]'
    # alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
spec:
  tls:
    - hosts:
      - order.live.shinetribe.media
      secretName: merchie-tls
  rules:
  - host: order.live.shinetribe.media
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: merchie
            port:
              name: api
```

How It Works
------------
cert-manager processes the `Certifiate` and creates a `Secret` with these annotation...

```
  "cert-secret-syncer/backend": "ACM"
  "cert-secret-syncer/ingress-labels": "app=merchie"
```

`cert-secret-syncer` picks this up, pushes the Certificate to ACM and retrieves the ARN. It applies the ARN to the Secret as an annotation and when the Secret changes, it retrieves the ARN from the Secret to update the ACM Certificate tied to the ARN.

It also applies the ARN to any Ingresses that match the `ingress-labels` label selector. It applies the ARN as the value to the `alb.ingress.kubernetes.io/certificate-arn` annotation so that the ALB knows what certificate to load to terminate TLS.
