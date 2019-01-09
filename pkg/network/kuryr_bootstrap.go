package network

import (
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	"log"
	"net"

	"github.com/pkg/errors"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/subnetpools"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"

	netv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"
)

func tagResource(client *gophercloud.ServiceClient, resource, id, tag string) ([]string, error) {
	tagOpts := attributestags.ReplaceAllOpts{Tags: []string{tag}}
	return attributestags.ReplaceAll(client, resource, id, tagOpts).Extract()
}

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

		_, err = tagResource(client, "networks", netObj.ID, tag)
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

		_, err = tagResource(client, "subnetpools", subnetpoolObj.ID, tag)
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created subnetpool")
		}

		return subnetpoolObj.ID, nil
	}
}

func findSubnetId(client *gophercloud.ServiceClient, name, tag string) (string, error) {
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

		_, err = tagResource(client, "subnets", subnetObj.ID, tag)
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created subnet")
		}

		return subnetObj.ID, nil
	}
}

func findRouterId(client *gophercloud.ServiceClient, name, tag string) (string, error) {
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

		_, err = tagResource(client, "ports", portObj.ID, tag)
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created port")
		}

		return portObj.ID, nil
	}
}

func findSgId(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := groups.List(client, groups.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed get SG list")
	}
	sgs, err := groups.ExtractGroups(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract SG list")
	}

	if len(sgs) == 1 {
		return sgs[0].ID, nil
	} else if len(sgs) == 0 {
		return "", errors.New("SG not found")
	} else {
		return "", errors.New("multiple matching SGs")
	}
}

func ensureSg(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	sgId, err := findSgId(client, name, tag)
	if err == nil {
		return sgId, nil
	} else {
		opts := groups.CreateOpts{
			Name: name,
		}
		sg, err := groups.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create SG")
		}

		_, err = tagResource(client, "security-groups", sg.ID, tag)
		if err != nil {
			return "", errors.Wrap(err, "failed to tag created SG")
		}

		return sg.ID, nil
	}
}

func ensureSgRule(client *gophercloud.ServiceClient, sgId, remoteSgId string) (error) {
	opts := rules.CreateOpts{
		SecGroupID: sgId,
		EtherType: rules.EtherType4,
		Direction: rules.DirIngress,
		RemoteGroupID: remoteSgId,
	}
	_, err := rules.Create(client, opts).Extract()
	if err != nil {
		if errCode, ok := err.(gophercloud.ErrUnexpectedResponseCode); ok {
			if errCode.Actual == 409 {
				// Ignoring 409 Conflict as that means the rule is already there.
				return nil
			}
		}
		return errors.Wrap(err, "failed to create SG rule")
	}
	return nil
}

func ensureLb(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	opts = loadbalancers.CreateOpts{
		Name: name,
	}
	loadbalancers.Create(opts)
}

func bootstrapKuryr(conf *netv1.NetworkConfigSpec) (*BootstrapData, error) {
	log.Print("Kuryr bootstrap started")
	kc := conf.DefaultNetwork.KuryrConfig
	creds := conf.DefaultNetwork.KuryrConfig.OpenStackCredentials
	region = "RegionOne" // TODO(dulek): How do I get the region?

	log.Printf("Connecting to OpenStack cloud %s, region %s as %s", creds.AuthURL, region, creds.Username)
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
		Region: region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Neutron client")
	}

	tag := "openshiftClusterID=" + kc.ClusterId
	log.Printf("Using %s as resources tag", tag)

	log.Print("Ensuring services network")
	svcNetId, err := ensureNetwork(client, "kuryr-service-network", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create service network")
	}
	log.Printf("Services network %s present", svcNetId)

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
	log.Printf("Ensuring services subnet with %s CIDR and %s gateway", conf.ServiceNetwork, ipStr)
	svcSubnetId, err := ensureSubnet(client, "kuryr-service-subnet", tag,
		svcNetId, conf.ServiceNetwork, &ipStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create service subnet")
	}
	log.Printf("Services subnet %s present", svcSubnetId)

	// Pod subnetpool
	cidrs := make([]string, len(conf.ClusterNetworks))
	for i, cn := range conf.ClusterNetworks {
		cidrs[i] = cn.CIDR
	}
	log.Printf("Ensuring pod subnetpool with following CIDRs: %v", cidrs)
	podSubnetpoolId, err := ensureSubnetpool(client, "kuryr-pod-subnetpool", tag, cidrs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create pod subnetpool")
	}
	log.Printf("Pod subnetpool %s present", podSubnetpoolId)

	workerSubnetId, err := findSubnetId(client, "nodes", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes subnet")
	}
	log.Printf("Found worker nodes subnet %s", workerSubnetId)
	routerId, err := findRouterId(client, "openshift-external-router", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes router")
	}
	log.Printf("Found worker nodes router %s", routerId)
	ps, err := getRouterPorts(client, routerId)
	if err != nil {
		return nil, errors.Wrap(err, "failed list ports of worker nodes router")
	}

	if !lookupPort(ps, svcSubnetId) {
		log.Printf("Ensuring service subnet router port with %s IP", ipStr)
		portId, err := ensurePort(client, "kuryr-service-subnet-router-port", tag,
			svcNetId, svcSubnetId, ipStr)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create service subnet router port")
		}
		log.Printf("Service subnet router port %s present, adding it as interface.", portId)
		err = ensureRouterInterface(client, routerId, nil, &portId)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create service subnet router interface")
		}
	}

	masterSgId, err := findSgId(client, "master", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find master nodes security group")
	}
	log.Printf("Found master nodes security group %s", masterSgId)
	workerSgId, err := findSgId(client, "worker", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes security group")
	}
	log.Printf("Found worker nodes security group %s", workerSgId)

	log.Print("Ensuring pods security group")
	podSgId, err := ensureSg(client, "kuryr-pods-security-group", tag)
	log.Printf("Pods security group %s present", podSgId)

	log.Print("Allowing traffic from masters and nodes to pods")
	err = ensureSgRule(client, podSgId, masterSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic from masters")
	}
	err = ensureSgRule(client, podSgId, workerSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic from workers")
	}
	err = ensureSgRule(client, masterSgId, podSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic to masters")
	}
	err = ensureSgRule(client, workerSgId, podSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic to workers")
	}
	log.Print("All requried traffic allowed")

	//TODO(dulek): Load balancer
	lb_client, err := openstack.NewLoadBalancerV2(provider, gophercloud.EndpointOpts{
		Name:   "octavia",
		Region: region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Octavia client")
	}

	log.Print("Creating OpenShift API loadbalancer")

	log.Print("Kuryr bootstrap finished")
	res := BootstrapData {
		Kuryr: KuryrBootstrapData {
			ServiceSubnet: svcSubnetId,
			PodSubnetpool: podSubnetpoolId,
			WorkerNodesRouter: routerId,
			WorkerNodesSubnet: workerSubnetId,
			PodSecurityGroups: []string{podSgId},
		}}
	return &res, nil
}

