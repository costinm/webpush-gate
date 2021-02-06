package cloudevents

import (
	"log"

	containerpb 	"google.golang.org/genproto/googleapis/container/v1"

	"cloud.google.com/go/container/apiv1"
	"context"
	"testing"
)

func TestGKE(t *testing.T) {
	ctx := context.Background()
	cl, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.ListClusters(ctx, &containerpb.ListClustersRequest{})
	log.Println(resp)
}


