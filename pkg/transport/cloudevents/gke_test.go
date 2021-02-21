package cloudevents

import (
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/api/iterator"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	containerpb "google.golang.org/genproto/googleapis/container/v1"

	"context"
	"testing"

	"cloud.google.com/go/container/apiv1"
)

// name:"big1"
// node_config:{machine_type:"n1-standard-32"  disk_size_gb:300
// oauth_scopes:"https://www.googleapis.com/auth/devstorage.read_only"  oauth_scopes:"https://www.googleapis.com/auth/logging.write"  oauth_scopes:"https://www.googleapis.com/auth/monitoring"
// oauth_scopes:"https://www.googleapis.com/auth/servicecontrol"  oauth_scopes:"https://www.googleapis.com/auth/service.management.readonly"  oauth_scopes:"https://www.googleapis.com/auth/trace.append"
// service_account:"default"
// metadata:{key:"disable-legacy-endpoints"  value:"true"}
// image_type:"COS"  disk_type:"pd-standard"
// shielded_instance_config:{enable_integrity_monitoring:true}
// 14:"\x10\x02"}

// master_auth:{cluster_ca_certificate:"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURERENDQWZTZ0F3SUJBZ0lSQUxGaVN6TU43RUljM2pMZE96ODNsbVl3RFFZSktvWklodmNOQVFFTEJRQXcKTHpFdE1Dc0dBMVVFQXhNa1lXUTJZVGxpTXpRdE5tVXdPUzAwWVRjeExUZzBaamt0TlRZd09UaGhaamxpWkRjMgpNQjRYRFRJd01EWXhOVEU0TURFeU5sb1hEVEkxTURZeE5ERTVNREV5Tmxvd0x6RXRNQ3NHQTFVRUF4TWtZV1EyCllUbGlNelF0Tm1Vd09TMDBZVGN4TFRnMFpqa3ROVFl3T1RoaFpqbGlaRGMyTUlJQklqQU5CZ2txaGtpRzl3MEIKQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdXc2bjlDV2sycitabDZibFJTeDVXdVFYYlNpdk9LQkhVVDVZOWZTMgo0TS9mUGUzaHNCRnYzS2hCTWM4dGI2cStDdnBIaFN4Y0xNdzEydit2RWMrcklxTmI2c3loZmpkL1owK1dGZm11CnEwcS94YkZXT3FCTG9NZlU5MzNmNmhNMi9vbmxqaDlRZzJlQ24zMzZSQ2t1ZE1yRjRMMHc2dnkwZHJvQ2VSTnQKNHdUYTJjT0dodXk0aWRsNkQ5cjF4QUp1MUdIUUROS29XeUMwdEVCcURUQU5UNkI2RkpPR1lZeHQ0bko1U1ExRQpSTU5Pb2VKNDdPWWtDT1pJeWh3WXdzeG90T0hnSmc0UFlqV2dIZnRlOXZkSVZJdUhMKzFoWS9CNmUvTmpIVjZoClRpOXoyWHd0MEpydkQvRzVoVENmVkhjZ2diQ1lKeEFBSHhDekdIWm9OUUJONFFJREFRQUJveU13SVRBT0JnTlYKSFE4QkFmOEVCQU1DQWdRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQQpack9Gby80Vkxiejg4TDVteGJQN084VWNZbDlkT2hvb0gwdU95UzJhczZQWVJ0NlNSSEZUZUdEY0xveUdveUFKCjZtKzlIMm1nQ3lmZVBqNjZDRDJlTE0yUTQyaVVOcW1yTDdvaUFpTlZVMUdpYzNaRzJubUIwU2Fkb1VGOW9KaU0KYVcwZENRMFhvdFIyZUNBUE03YlRPMHJFbkd2dEpFaDJRSFVOUXNiRVBmUlV2MTBmV2t6blg0ZGhUOE9BWXdoWQpFb3JzMjVyR0V0OTROTUI0RzdIeXUzMmFMNmlGUVFjWTlaWmsycWViSWRvM0dRR0huYmRTV3o0RS95OVZqS25lCmZBaWFTcys5RXpja1VPTnM1WDk3WTNtMyt3NGpwbjZaejlsanhUaVlaN29VTFg5a2k3cGxpQklKbnB6aTZPUzEKWHhXNmcwTGFyRldmZU9hbDBNN3Ewdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"}

// logging_service:"logging.googleapis.com/kubernetes"
// monitoring_service:"monitoring.googleapis.com/kubernetes"
// network:"default"  cluster_ipv4_cidr:"10.48.0.0/14"
// addons_config:{http_load_balancing:{}
// horizontal_pod_autoscaling:{}
// kubernetes_dashboard:{disabled:true}
// network_policy_config:{}
// cloud_run_config:{disabled:true  3:1}
// 8:"\x08\x01"  10:""  11:""}
// subnetwork:"default"


// node_pools:{name:"default-pool"
//  config:{machine_type:"n1-standard-32"  disk_size_gb:300
//   oauth_scopes:"https://www.googleapis.com/auth/devstorage.read_only"  oauth_scopes:"https://www.googleapis.com/auth/logging.write"  oauth_scopes:"https://www.googleapis.com/auth/monitoring"
//   oauth_scopes:"https://www.googleapis.com/auth/servicecontrol"  oauth_scopes:"https://www.googleapis.com/auth/service.management.readonly"
//   oauth_scopes:"https://www.googleapis.com/auth/trace.append"
//   service_account:"default"
//   metadata:{key:"disable-legacy-endpoints"  value:"true"}
//   image_type:"COS"  disk_type:"pd-standard"  shielded_instance_config:{enable_integrity_monitoring:true}
//   14:"\x10\x02"}
//  initial_node_count:1
//  self_link:"https://container.googleapis.com/v1/projects/costin-asm1/zones/us-central1-c/clusters/big1/nodePools/default-pool"
//  version:"1.18.12-gke.1205"
//  instance_group_urls:"https://www.googleapis.com/compute/v1/projects/costin-asm1/zones/us-central1-c/instanceGroupManagers/gke-big1-default-pool-2f5f5ceb-grp"
//  status:RUNNING
//  autoscaling:{}
//  management:{auto_upgrade:true  auto_repair:true}
//  max_pods_constraint:{max_pods_per_node:110}
//   conditions:{message:"Insufficient quota to satisfy the request: waiting on IG: instance https://www.googleapis.com/compute/v1/projects/costin-asm1/zones/us-central1-c/instances/gke-big1-default-pool-2f5f5ceb-mnar is still CREATING. Last
//      attempt error: [QUOTA_EXCEEDED] Instance 'gke-big1-default-pool-2f5f5ceb-mnar' creation failed: Quota 'CPUS' exceeded.
//      Limit: 72.0 in region us-central1. - ."}
//  pod_ipv4_cidr_size:24
//  13:"us-central1-c"
//  107:"\x08\x01\x10\x01"}
//
// locations:"us-central1-c"
// resource_labels:{key:"asmv"  value:"1-8-1-asm-2"}
// resource_labels:{key:"mesh_id"  value:"proj-438684899409"}
// label_fingerprint:"3b27cb4b"
// legacy_abac:{}  network_policy:{provider:CALICO  enabled:true}
// ip_allocation_policy:{use_ip_aliases:true cluster_ipv4_cidr:"10.48.0.0/14"  services_ipv4_cidr:"10.0.0.0/20"
//   cluster_secondary_range_name:"gke-big1-pods-6c27336c"
//   services_secondary_range_name:"gke-big1-services-6c27336c"  cluster_ipv4_cidr_block:"10.48.0.0/14"  services_ipv4_cidr_block:"10.0.0.0/20"}
// master_authorized_networks_config:{}
// maintenance_policy:{resource_version:"e3b0c442"}
// network_config:{network:"projects/costin-asm1/global/networks/default"  subnetwork:"projects/costin-asm1/regions/us-central1/subnetworks/default"}
// default_max_pods_constraint:{max_pods_per_node:110}
// authenticator_groups_config:{}
// database_encryption:{state:DECRYPTED}
// self_link:"https://container.googleapis.com/v1/projects/costin-asm1/zones/us-central1-c/clusters/big1"
// zone:"us-central1-c"
// endpoint:"35.193.24.39"
// initial_cluster_version:"1.17.5-gke.9"
// current_master_version:"1.18.12-gke.1205"
// current_node_version:"1.18.12-gke.1205"
// create_time:"2020-06-15T19:01:26+00:00"
// status:RUNNING
// services_ipv4_cidr:"10.0.0.0/20"
// instance_group_urls:"https://www.googleapis.com/compute/v1/projects/costin-asm1/zones/us-central1-c/instanceGroupManagers/gke-big1-default-pool-2f5f5ceb-grp"
// current_node_count:1
// location:"us-central1-c"
// 40:""  41:"\x08\x01"  43:"\x12\x17costin-asm1.svc.id.goog"

func TestGKE(t *testing.T) {
	ctx := context.Background()
	cl, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.ListClusters(ctx, &containerpb.ListClustersRequest{
		Parent: "projects/costin-asm1/locations/-",
	})
	if err == nil {
		for _, c := range resp.Clusters {
			log.Println(c.Name, c.Location, c.Endpoint, c.MasterAuth.ClusterCaCertificate)
		}
		c, err := cl.GetCluster(ctx, &containerpb.GetClusterRequest{
			Name: "projects/costin-asm1/locations/us-central1-c/cluster/cloudrun",
		})
		if err != nil {
			t.Fatal(err)
		}
		log.Println(c.Name)
	}

	sc, err := secretmanager.NewClient(ctx)
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: "projects/dmeshgate",
	}
	it := sc.ListSecrets(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Println(err)
			break
		}
		// TODO: Use resp.
		//log.Println(resp)
		s1, err := sc.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
			Name: resp.Name + "/versions/latest",
		})
		if err == nil {
			log.Println(resp.Name, s1.Name, len(s1.GetPayload().Data))
			log.Println(string(s1.Payload.Data))
		} else {
			log.Println(resp.Name, err)
		}
	}
}


