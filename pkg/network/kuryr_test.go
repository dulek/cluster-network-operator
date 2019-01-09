package network

import (
	"testing"

	netv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"

	. "github.com/onsi/gomega"
)

var KuryrConfig = netv1.NetworkConfig{
	Spec: netv1.NetworkConfigSpec{
		ServiceNetwork: "172.30.0.0/16",
		ClusterNetworks: []netv1.ClusterNetwork{
			{
				CIDR:             "10.128.0.0/15",
				HostSubnetLength: 9,
			},
		},
		DefaultNetwork: netv1.DefaultNetworkDefinition{
			Type: netv1.NetworkTypeKuryr,
			KuryrConfig: &netv1.KuryrConfig{
				OpenStackCredentials: &netv1.OpenStackCredentials{
					AuthURL: "authurl",
					UserDomainName: "udn",
					Username: "user",
					Password: "password",
					ProjectDomainName: "pdn",
					ProjectId: "pid",
				},
				ClusterId: "cluster-id",
			},
		},
	},
}

var FakeBootstrapData = BootstrapData {
	Kuryr: KuryrBootstrapData{
		PodSubnetpool: "pod-subnetpool-id",
		ServiceSubnet: "svc-subnet-id",
	},
}

// TestRenderKuryr has some simple rendering tests
func TestRenderKuryr(t *testing.T) {
	g := NewGomegaWithT(t)

	crd := KuryrConfig.DeepCopy()
	config := &crd.Spec

	errs := validateKuryr(config)
	g.Expect(errs).To(HaveLen(0))

	objs, err := renderKuryr(config, FakeBootstrapData, manifestDir)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(objs).To(ContainElement(HaveKubernetesID("DaemonSet", "kuryr", "kuryr-cni")))

	// It's important that the namespace is before any namespaced types;
	// for now, just test that it's the second item in the list, after
	// the ClusterNetwork.
	g.Expect(objs[0]).To(HaveKubernetesID("Namespace", "", "kuryr"))

	g.Expect(objs).To(ContainElement(HaveKubernetesID("ClusterRole", "", "kuryr")))
	g.Expect(objs).To(ContainElement(HaveKubernetesID("ServiceAccount", "kuryr", "kuryr")))
	g.Expect(objs).To(ContainElement(HaveKubernetesID("ClusterRoleBinding", "", "kuryr")))
	g.Expect(objs).To(ContainElement(HaveKubernetesID("Deployment", "kuryr", "kuryr-controller")))
	g.Expect(objs).To(ContainElement(HaveKubernetesID("ConfigMap", "kuryr", "kuryr-config")))
	g.Expect(objs).To(ContainElement(HaveKubernetesID("Secret", "kuryr", "kuryr-certificates")))
	g.Expect(objs).To(ContainElement(HaveKubernetesID("CustomResourceDefinition", "", "kuryrnets.openstack.org")))
}

func TestValidateKuryr(t *testing.T) {
	g := NewGomegaWithT(t)

	crd := KuryrConfig.DeepCopy()
	config := &crd.Spec
	kuryrConfig := config.DefaultNetwork.KuryrConfig

	err := validateKuryr(config)
	g.Expect(err).To(BeEmpty())

	errExpect := func(substr string) {
		t.Helper()
		g.Expect(validateKuryr(config)).To(
			ContainElement(MatchError(
				ContainSubstring(substr))))
	}

	kuryrConfig.OpenStackCredentials.AuthURL = ""
	errExpect("AuthURL cannot be empty")

	kuryrConfig.OpenStackCredentials.Username = ""
	errExpect("Username cannot be empty")

	kuryrConfig.OpenStackCredentials.Password = ""
	errExpect("Password cannot be empty")

	kuryrConfig.OpenStackCredentials.ProjectDomainName = ""
	errExpect("ProjectDomainName cannot be empty")

	kuryrConfig.OpenStackCredentials.UserDomainName = ""
	errExpect("UserDomainName cannot be empty")

	kuryrConfig.OpenStackCredentials.ProjectId = ""
	errExpect("ProjectId cannot be empty")
}
