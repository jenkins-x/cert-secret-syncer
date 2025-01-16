package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/jenkins-x/cert-secret-syncer/util"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type SecretSyncer struct {
	Ctx context.Context
	client.Client
}

var awsAcmSvc *acm.ACM

func init() {
	// Create ACM service client
	awsAcmSvc = acm.New(session.Must(session.NewSession()))
}

func (r *SecretSyncer) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx)

	// Get the secret
	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, client.IgnoreNotFound(err)
	}

	// Check annotations
	backend, ok := secret.Annotations["cert-secret-syncer/backend"]
	if !ok {
		return ctrl.Result{}, nil
	}

	switch backend {
	case "ACM":
		logger.Info("reconciling secret with AWS Certificate Manager backend")

		// Read certificate and key
		var certs [][]byte
		var key []byte
		{
			cert, ok := secret.Data["tls.crt"]
			if !ok {
				return ctrl.Result{}, fmt.Errorf("cert not found in secret data")
			}
			certs, err = splitPEMCertificates(cert)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("could not split certs: %v", err)
			}

			key, ok = secret.Data["tls.key"]
			if !ok {
				return ctrl.Result{}, fmt.Errorf("key not found in secret data")
			}
		}

		// Get certificate arn to update
		certificateArn := secret.Annotations["alb.ingress.kubernetes.io/certificate-arn"]

		// Import certificate to ACM
		logger.Info("importing cert to ACM")

		importCertInput := &acm.ImportCertificateInput{
			Certificate: certs[0],
			PrivateKey:  key,
		}
		if certificateArn != "" {
			importCertInput.CertificateArn = &certificateArn
		}
		if len(certs) > 1 {
			importCertInput.CertificateChain = appendByteSlices(certs[1:])
		}

		output, err := awsAcmSvc.ImportCertificate(importCertInput)
		if err != nil {
			return ctrl.Result{RequeueAfter: time.Minute}, fmt.Errorf("failed to import the certificate: %v", err)
		}

		// is this is the first import?
		if certificateArn == "" {
			// yes... save the ARN on the secret
			secret.Annotations["alb.ingress.kubernetes.io/certificate-arn"] = *output.CertificateArn
			err = r.Update(ctx, secret)
			if err != nil {
				return ctrl.Result{RequeueAfter: time.Minute}, fmt.Errorf("failed to update the secret: %v", err)
			}
		}

		certificateArn = *output.CertificateArn

		// update the ingress with the certificate-arn
		ingressLabelsAsString, ok := secret.Annotations["cert-secret-syncer/ingress-labels"]
		if ok {
			ingressLabels, err := r.labelStringParse(ingressLabelsAsString)
			if err != nil {
				return ctrl.Result{RequeueAfter: time.Minute}, fmt.Errorf("failed to parse ingress labels '%s': %v", ingressLabelsAsString, err)
			}

			ingresses, err := r.ingressesGetByLabels(ctx, ingressLabels)
			if err != nil {
				return ctrl.Result{RequeueAfter: time.Minute}, fmt.Errorf("ingresses not found by labels '%s': %v", ingressLabelsAsString, err)
			}

			for _, ingress := range ingresses.Items {
				ingress.Annotations["alb.ingress.kubernetes.io/certificate-arn"] = certificateArn
				err = r.Update(ctx, &ingress)
				if err != nil {
					return ctrl.Result{RequeueAfter: time.Minute}, fmt.Errorf("failed to update ingress: %v", err)
				}
			}
		}

		// Handle other backends
	}

	return ctrl.Result{}, nil
}

func (r *SecretSyncer) ingressesGetByLabels(ctx context.Context, labelSet map[string]string) (*networkingv1.IngressList, error) {
	listOpts := &client.ListOptions{
		LabelSelector: labels.Set(labelSet).AsSelector(),
	}

	ingresses := &networkingv1.IngressList{}
	err := r.List(ctx, ingresses, listOpts)
	return ingresses, err
}

func (r *SecretSyncer) labelStringParse(labelString string) (map[string]string, error) {
	labelMap := map[string]string{}

	pairs := strings.Split(labelString, ",")
	for _, pair := range pairs {
		kv := strings.Split(strings.TrimSpace(pair), "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid label spec: %q", pair)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		if key == "" {
			return nil, fmt.Errorf("invalid label spec: %q", pair)
		}

		labelMap[key] = value
	}

	return labelMap, nil

}

func main() {
	var err error

	check := func(err error) {
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	logger := util.LogNew()
	log.SetLogger(logger)
	ctx := log.IntoContext(context.Background(), logger)

	logger.Info("starting controller")
	logger.Info(`set these annotations to sync your secrets with AWS Certificate Manager:
		 cert-secret-syncer/backend: "ACM"
		 cert-secret-syncer/ingress-labels: "app=nginx,env=production"`)

	scheme := runtime.NewScheme()
	err = corev1.AddToScheme(scheme)
	check(err)
	err = networkingv1.AddToScheme(scheme)
	check(err)

	// Set up the controller manager to cache only Secrets
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Cache:                  cache.Options{ByObject: map[client.Object]cache.ByObject{&corev1.Secret{}: {}}},
		HealthProbeBindAddress: "0.0.0.0:8081",
		Metrics:                metricsserver.Options{BindAddress: "0.0.0.0:8080"},
		Scheme:                 scheme,
	})
	check(err)

	err = mgr.AddHealthzCheck("healthz", healthz.Ping)
	check(err)

	err = mgr.AddReadyzCheck("readyz", healthz.Ping)
	check(err)

	// create a new controller managed by the manager
	c, err := controller.New("cert-secret-syncer", mgr, controller.Options{
		Reconciler:       &SecretSyncer{Ctx: ctx, Client: mgr.GetClient()},
		CacheSyncTimeout: time.Minute,
	})
	check(err)

	// have the controller watch secrets on the manager's cache
	err = c.Watch(source.Kind(mgr.GetCache(), &corev1.Secret{}, &handler.TypedEnqueueRequestForObject[*corev1.Secret]{}))
	check(err)

	// start all controllers under the manager
	logger.Info("starting")
	if err := mgr.Start(ctx); err != nil {
		logger.Error(err, "controller error")
		os.Exit(1)
	}

	os.Exit(0)
}
