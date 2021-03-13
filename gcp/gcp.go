package gcp

import (
	"encoding/base64"
	"fmt"
	"context"

	containerpb "google.golang.org/genproto/googleapis/container/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"cloud.google.com/go/container/apiv1"

	// Required
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func InitK8S(p, l, clusterName string) (*kubernetes.Clientset, error) {
	ctx := context.Background()

	cl, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, err
	}

	c, err := cl.GetCluster(ctx, &containerpb.GetClusterRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/cluster/%s", p, l, clusterName),
	})
	if err != nil {
		return nil, err
	}

	//	kcs := `
	//apiVersion: v1
	//kind: Config
	//current-context: my-cluster
	//contexts: [{name: my-cluster, context: {cluster: cluster-1, user: user-1}}]
	//users: [{name: user-1, user: {auth-provider: {name: gcp}}}]
	//clusters:
	//- name: cluster-1
	//  cluster:
	//    server: "https://%s"
	//    certificate-authority-data: "%s"
	//
	//`
	//	kcsp := fmt.Sprintf(kcs, c.Endpoint, c.MasterAuth.ClusterCaCertificate)
	//	cfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(kcsp))
	caCert, err := base64.StdEncoding.DecodeString(c.MasterAuth.ClusterCaCertificate)
	if err != nil {
		return nil, err
	}
	cfg := &rest.Config{
		Host: "https://" + c.Endpoint,
		AuthProvider: &clientcmdapi.AuthProviderConfig{
			Name: "gcp",
		},
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caCert,
		},
	}

	cfg.TLSClientConfig.CAData = caCert

	kc,err  := kubernetes.NewForConfig(cfg)

	return kc, nil
}
