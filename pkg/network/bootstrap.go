package network

import (
	"github.com/pkg/errors"

	netv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"
)

type KuryrBootstrapData struct {
	ServiceSubnet string
	PodSubnetpool string
	WorkerNodesRouter string
	WorkerNodesSubnet string
}

type BootstrapData struct {
	Kuryr KuryrBootstrapData
}

// Bootstrap creates resources required by SDN on the cloud.
func Bootstrap(conf *netv1.NetworkConfigSpec) (*BootstrapData, error) {
	switch conf.DefaultNetwork.Type {
	case netv1.NetworkTypeKuryr:
		return bootstrapKuryr(conf)
	case netv1.NetworkTypeOpenShiftSDN, netv1.NetworkTypeDeprecatedOpenshiftSDN:
		return nil, nil
	}

	return nil, errors.Errorf("unknown or unsupported NetworkType: %s", conf.DefaultNetwork.Type)
}
