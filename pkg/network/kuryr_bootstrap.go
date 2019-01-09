package network

import (
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/subnetpools"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"net"

	"github.com/pkg/errors"

	netv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"
)

func ensureNetwork(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := networks.List(client, networks.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed get network list")
	}
	nets, err := networks.ExtractNetworks(page)
	if err != nil {
		return "", errors.Wrap(err, "failed extract networks list")
	}
	if len(nets) == 1 {
		return nets[0].ID, nil
	} else {
		opts := networks.CreateOpts{
			Name: name,
		}
		netObj, err := networks.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create network")
		}

		tagOpts := attributestags.ReplaceAllOpts{Tags: []string{tag}}
		_, err = attributestags.ReplaceAll(client, "networks", netObj.ID, tagOpts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created network")
		}

		return netObj.ID, nil
	}
}

func ensureSubnetpool(client *gophercloud.ServiceClient, name, tag string, cidrs []string) (string, error) {
	page, err := subnetpools.List(client, subnetpools.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed get subnet list")
	}
	sp, err := subnetpools.ExtractSubnetPools(page)
	if err != nil {
		return "", errors.Wrap(err, "failed extract subnetpools list")
	}
	if len(sp) == 1 {
		return sp[0].ID, nil
	} else {
		opts := subnetpools.CreateOpts{
			Name: name,
			Prefixes: cidrs,
			DefaultPrefixLen: 24,
		}
		subnetpoolObj, err := subnetpools.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create subnetpool")
		}

		tagOpts := attributestags.ReplaceAllOpts{Tags: []string{tag}}
		_, err = attributestags.ReplaceAll(client, "subnetpools", subnetpoolObj.ID, tagOpts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created subnetpool")
		}

		return subnetpoolObj.ID, nil
	}
}

func findSubnetId(client *gophercloud.ServiceClient, name string, tag string) (string, error) {
	page, err := subnets.List(client, subnets.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed get subnet list")
	}
	subnetList, err := subnets.ExtractSubnets(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract subnets list")
	}
	if len(subnetList) == 1 {
		return subnetList[0].ID, nil
	} else if len(subnetList) == 0 {
		return "", errors.New("subnet not found")
	} else {
		return "", errors.New("multiple matching subnets")
	}
}

func ensureSubnet(client *gophercloud.ServiceClient, name, tag, netId, cidr string, gatewayIp *string) (string, error) {
	subnetId, err := findSubnetId(client, name, tag)
	if err == nil {
		return subnetId, nil
	} else {
		opts := subnets.CreateOpts{
			Name:      name,
			NetworkID: netId,
			CIDR:      cidr,
			GatewayIP: gatewayIp,
			IPVersion: gophercloud.IPv4,
		}
		subnetObj, err := subnets.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create subnet")
		}

		tagOpts := attributestags.ReplaceAllOpts{Tags: []string{tag}}
		_, err = attributestags.ReplaceAll(client, "subnets", subnetObj.ID, tagOpts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created subnet")
		}

		return subnetObj.ID, nil
	}
}

func findRouterId(client *gophercloud.ServiceClient, name string, tag string) (string, error) {
	page, err := routers.List(client, routers.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed get router list")
	}
	routerList, err := routers.ExtractRouters(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract routers list")
	}

	if len(routerList) == 1 {
		return routerList[0].ID, nil
	} else if len(routerList) == 0 {
		return "", errors.New("router not found")
	} else {
		return "", errors.New("multiple matching routers")
	}
}

func getRouterPorts(client *gophercloud.ServiceClient, routerId string) ([]ports.Port, error) {
	page, err := ports.List(client, ports.ListOpts{DeviceID: routerId}).AllPages()
	if err != nil {
		return []ports.Port{}, errors.Wrap(err, "failed get port list")
	}
	ps, err := ports.ExtractPorts(page)
	if err != nil {
		return []ports.Port{}, errors.Wrap(err, "failed to extract port list")
	}
	return ps, nil
}

func lookupPort(ps []ports.Port, subnetId string) bool {
	for _, port := range ps {
		for _, ip := range port.FixedIPs {
			if ip.SubnetID == subnetId {
				return true
			}
		}
	}
	return false
}

func ensureRouterInterface(client *gophercloud.ServiceClient, routerId string, subnetId, portId *string) error {
	opts := routers.AddInterfaceOpts{}
	if subnetId != nil {
		opts.SubnetID = *subnetId
	}
	if portId != nil {
		opts.PortID = *portId
	}
	_, err := routers.AddInterface(client, routerId, opts).Extract()
	if err != nil {
		return errors.Wrap(err, "failed to add interface")
	}
	return nil
}

func ensurePort(client *gophercloud.ServiceClient, name, tag, netId, subnetId, ip string) (string, error) {
	page, err := ports.List(client, ports.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed get port list")
	}
	portList, err := ports.ExtractPorts(page)
	if err != nil {
		return "", errors.Wrap(err, "failed extract ports list")
	}
	if len(portList) == 1 {
		return portList[0].ID, nil
	} else {
		opts := ports.CreateOpts{
			Name: name,
			NetworkID: netId,
			FixedIPs: []ports.IP{{SubnetID: subnetId, IPAddress: ip}},
		}
		portObj, err := ports.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create port")
		}

		tagOpts := attributestags.ReplaceAllOpts{Tags: []string{tag}}
		_, err = attributestags.ReplaceAll(client, "ports", portObj.ID, tagOpts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created port")
		}

		return portObj.ID, nil
	}
}

func bootstrapKuryr(conf *netv1.NetworkConfigSpec) (*BootstrapData, error) {
	kc := conf.DefaultNetwork.KuryrConfig
	creds := conf.DefaultNetwork.KuryrConfig.OpenStackCredentials

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: creds.AuthURL,
		Username:         creds.Username,
		Password:         creds.Password,
		TenantID:         creds.ProjectId,
		DomainName:       creds.ProjectDomainName, // TODO(dulek): Make sure that's the one.
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate to OpenStack")
	}

	client, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Name:   "neutron",
		Region: "RegionOne", // TODO(dulek): How do I get the region?
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Neutron client")
	}

	tag := "openshiftClusterID=" + kc.ClusterId

	// Service network
	svcNetId, err := ensureNetwork(client, "kuryr-service-network", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create service network")
	}

	// Service subnet
	// We need second to last IP from this CIDR
	_, svcNet, err := net.ParseCIDR(conf.ServiceNetwork)
	// This will get us the last one
	ip := svcNet.IP
	mask := svcNet.Mask
	ip.Mask(mask)
	ip = net.IP{ip[0] | ^mask[0], ip[1] | ^mask[1], ip[2] | ^mask[2], ip[3] | ^mask[3]}
	// And this second to last
	ip[3] &= 0xFE
	ipStr := ip.String()
	svcSubnetId, err := ensureSubnet(client, "kuryr-service-subnet", tag,
		svcNetId, conf.ServiceNetwork, &ipStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create service subnet")
	}

	// Pod subnetpool
	cidrs := make([]string, len(conf.ClusterNetworks))
	for i, cn := range conf.ClusterNetworks {
		cidrs[i] = cn.CIDR
	}
	podSubnetpoolId, err := ensureSubnetpool(client, "kuryr-pod-subnetpool", tag, cidrs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create pod subnetpool")
	}

	workerSubnetId, err := findSubnetId(client, "nodes", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes subnet")
	}
	routerId, err := findRouterId(client, "openshift-external-router", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes router")
	}
	ps, err := getRouterPorts(client, routerId)
	if err != nil {
		return nil, errors.Wrap(err, "failed list ports of worker nodes router")
	}

	if !lookupPort(ps, svcSubnetId) {
		portId, err := ensurePort(client, "kuryr-service-subnet-router-port", tag,
			svcNetId, svcSubnetId, ipStr)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create service subnet router port")
		}
		err = ensureRouterInterface(client, routerId, nil, &portId)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create service subnet router interface")
		}
	}

	res := BootstrapData {
		Kuryr: KuryrBootstrapData {
			ServiceSubnet: svcSubnetId,
			PodSubnetpool: podSubnetpoolId,
			WorkerNodesRouter: routerId,
			WorkerNodesSubnet: workerSubnetId,
		}}
	return &res, nil
}

