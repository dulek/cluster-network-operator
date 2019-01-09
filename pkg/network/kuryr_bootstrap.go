package network

import (
	"log"
	"net"
	"regexp"

	"github.com/pkg/errors"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/pools"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
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

func ensureOpenStackNetwork(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := networks.List(client, networks.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get network list")
	}
	nets, err := networks.ExtractNetworks(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract networks list")
	}
	if len(nets) >1 {
		return "", errors.Errorf("found multiple networks matching name %s and tag %s, cannot proceed", name, tag)
	} else if len(nets) == 1 {
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

func ensureOpenStackSubnetpool(client *gophercloud.ServiceClient, name, tag string, cidrs []string) (string, error) {
	page, err := subnetpools.List(client, subnetpools.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get subnetpool list")
	}
	sp, err := subnetpools.ExtractSubnetPools(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract subnetpools list")
	}
	if len(sp) > 1 {
		return "", errors.Errorf("found multiple subnetpools matching name %s and tag %s, cannot proceed", name, tag)
	} else if len(sp) == 1 {
		// TODO(dulek): Check if it has correct CIDRs.
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

func findOpenStackSubnetId(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := subnets.List(client, subnets.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get subnet list")
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

func ensureOpenStackSubnet(client *gophercloud.ServiceClient, name, tag, netId, cidr string, gatewayIp *string) (string, error) {
	dhcp := false
	page, err := subnets.List(client, subnets.ListOpts{
		Name: name,
		Tags: tag,
		NetworkID: netId,
		CIDR: cidr,
		GatewayIP: *gatewayIp,
		IPVersion: 4,
		EnableDHCP: &dhcp,
	}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get subnet list")
	}
	subnetList, err := subnets.ExtractSubnets(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract subnets list")
	}
	if len(subnetList) > 1 {
		return "", errors.Errorf("found multiple subnets matching name %s and tag %s, cannot proceed", name, tag)
	} else if len(subnetList) == 1 {
		return subnetList[0].ID, nil
	} else {
		opts := subnets.CreateOpts{
			Name:      name,
			NetworkID: netId,
			CIDR:      cidr,
			GatewayIP: gatewayIp,
			IPVersion: gophercloud.IPv4,
			EnableDHCP: &dhcp,
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

func findOpenStackRouterId(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := routers.List(client, routers.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get router list")
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

func getOpenStackRouterPorts(client *gophercloud.ServiceClient, routerId string) ([]ports.Port, error) {
	page, err := ports.List(client, ports.ListOpts{DeviceID: routerId}).AllPages()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get port list")
	}
	ps, err := ports.ExtractPorts(page)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract port list")
	}
	return ps, nil
}

func lookupOpenStackPort(ps []ports.Port, subnetId string) bool {
	for _, port := range ps {
		for _, ip := range port.FixedIPs {
			if ip.SubnetID == subnetId {
				return true
			}
		}
	}
	return false
}

func ensureOpenStackRouterInterface(client *gophercloud.ServiceClient, routerId string, subnetId, portId *string) error {
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

func listOpenStackPortsMatchingPattern(client *gophercloud.ServiceClient, tag string, pattern *regexp.Regexp) ([]ports.Port, error) {
	page, err := ports.List(client, ports.ListOpts{Tags: tag}).AllPages()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get port list")
	}
	portList, err := ports.ExtractPorts(page)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract ports list")
	}
	result := []ports.Port{}
	for _, port := range portList {
		if pattern.MatchString(port.Name) {
			result = append(result, port)
		}
	}

	return result, nil
}

func ensureOpenStackPort(client *gophercloud.ServiceClient, name, tag, netId, subnetId, ip string) (string, error) {
	page, err := ports.List(client, ports.ListOpts{Name: name, Tags: tag, NetworkID: netId}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get port list")
	}
	portList, err := ports.ExtractPorts(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract ports list")
	}
	if len(portList) > 1 {
		return "", errors.Errorf("found multiple ports matching name %s, tag %s, cannot proceed", name, tag)
	} else if len(portList) == 1 {
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

func findOpenStackSgId(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := groups.List(client, groups.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get SG list")
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

func ensureOpenStackSg(client *gophercloud.ServiceClient, name, tag string) (string, error) {
	page, err := groups.List(client, groups.ListOpts{Name: name, Tags: tag}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get SG list")
	}
	sgs, err := groups.ExtractGroups(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract SG list")
	}
	if len(sgs) > 1 {
		return "", errors.Errorf("found multiple SG matching name %s, tag %s, cannot proceed", name, tag)
	} else if len(sgs) == 1 {
		return sgs[0].ID, nil
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

func ensureOpenStackSgRule(client *gophercloud.ServiceClient, sgId, remoteSgId string) (error) {
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

func waitForOpenStackLb(client *gophercloud.ServiceClient, lbId string) error {
	err := gophercloud.WaitFor(300, func() (bool, error) {
		lb, err := loadbalancers.Get(client, lbId).Extract()
		if err != nil {
			return false, err
		}

		if lb.ProvisioningStatus == "ACTIVE" {
			return true, nil
		}

		return false, nil
	})

	return err
}

func ensureOpenStackLb(client *gophercloud.ServiceClient, name, vipAddress, vipSubnetId string) (string, error) {
	page, err := loadbalancers.List(client, loadbalancers.ListOpts{
		Name:        name,
		VipAddress:  vipAddress,
		VipSubnetID: vipSubnetId,
	}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get LB list")
	}
	lbs, err := loadbalancers.ExtractLoadBalancers(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract LB list")
	}
	if len(lbs) > 1 {
		return "", errors.Errorf("found multiple LB matching name %s, cannot proceed", name)
	} else if len(lbs) == 1 {
		return lbs[0].ID, nil
	} else {
		opts := loadbalancers.CreateOpts{
			Name: name,
			VipAddress: vipAddress,
			VipSubnetID: vipSubnetId,
		}
		lb, err := loadbalancers.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create LB")
		}

		err = waitForOpenStackLb(client, lb.ID)
		if err != nil {
			return "", errors.Errorf("Timed out waiting for the LB %s to become ready", lb.ID)
		}

		return lb.ID, nil
	}
}

func ensureOpenStackLbPool(client *gophercloud.ServiceClient, name, lbId string) (string, error) {
	page, err := pools.List(client, pools.ListOpts{
		Name:           name,
		LoadbalancerID: lbId,
		Protocol:       "HTTPS",
		LBMethod:       "ROUND_ROBIN",
	}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get LB pools list")
	}
	poolsList, err := pools.ExtractPools(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract LB pools list")
	}
	if len(poolsList) > 1 {
		return "", errors.Errorf("found multiple LB pools matching name %s, LB %s, cannot proceed", name, lbId)
	} else if len(poolsList) == 1 {
		return poolsList[0].ID, nil
	} else {
		opts := pools.CreateOpts{
			Name: name,
			LoadbalancerID: lbId,
			Protocol: pools.ProtocolHTTPS,
			LBMethod: pools.LBMethodRoundRobin,
		}
		poolsObj, err := pools.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create LB pool")
		}

		err = waitForOpenStackLb(client, lbId)
		if err != nil {
			return "", errors.Errorf("Timed out waiting for the LB %s to become ready", lbId)
		}

		return poolsObj.ID, nil
	}
}

func ensureOpenStackLbPoolMember(client *gophercloud.ServiceClient, name, lbId, poolId,
	address, subnetId string, port int) (string, error) {
	page, err := pools.ListMembers(client, poolId, pools.ListMembersOpts{
		Name: name,
		Address: address,
		ProtocolPort: port,
	}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get LB member list")
	}
	members, err := pools.ExtractMembers(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract LB members list")
	}
	if len(members) > 1 {
		return "", errors.Errorf("found multiple LB members matching name %s, cannot proceed", name)
	} else if len(members) == 1 {
		return members[0].ID, nil
	} else {
		opts := pools.CreateMemberOpts{
			Name: name,
			Address: address,
			ProtocolPort: port,
			SubnetID: subnetId,
		}
		poolsObj, err := pools.CreateMember(client, poolId, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create LB member")
		}

		err = waitForOpenStackLb(client, lbId)
		if err != nil {
			return "", errors.Errorf("Timed out waiting for the LB %s to become ready", lbId)
		}

		return poolsObj.ID, nil
	}
}

func ensureOpenStackLbListener(client *gophercloud.ServiceClient, name, lbId, poolId string, port int) (string, error) {
	page, err := listeners.List(client, listeners.ListOpts{
		Name: name,
		Protocol: "HTTPS",
		ProtocolPort: port,
		DefaultPoolID: poolId,
		LoadbalancerID: lbId,
	}).AllPages()
	if err != nil {
		return "", errors.Wrap(err, "failed to get LB listeners list")
	}
	listenersList, err := listeners.ExtractListeners(page)
	if err != nil {
		return "", errors.Wrap(err, "failed to extract LB listeners list")
	}
	if len(listenersList) > 1 {
		return "", errors.Errorf("found multiple LB listeners matching name %s, LB %s, cannot proceed", name, lbId)
	} else if len(listenersList) == 1 {
		return listenersList[0].ID, nil
	} else {
		opts := listeners.CreateOpts{
			Name: name,
			Protocol: listeners.ProtocolHTTPS,
			ProtocolPort: port,
			DefaultPoolID: poolId,
			LoadbalancerID: lbId,
		}
		listenerObj, err := listeners.Create(client, opts).Extract()
		if err != nil {
			return "", errors.Wrap(err, "failed to create LB listener")
		}

		err = waitForOpenStackLb(client, lbId)
		if err != nil {
			return "", errors.Errorf("Timed out waiting for the LB %s to become ready", lbId)
		}

		return listenerObj.ID, nil
	}
}

func bootstrapKuryr(conf *netv1.NetworkConfigSpec) (*BootstrapData, error) {
	log.Print("Kuryr bootstrap started")
	kc := conf.DefaultNetwork.KuryrConfig
	creds := conf.DefaultNetwork.KuryrConfig.OpenStackCredentials
	region := creds.RegionName

	log.Printf("Connecting to OpenStack cloud %s, region %s as %s", creds.AuthURL, region, creds.Username)
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: creds.AuthURL,
		Username:         creds.Username,
		Password:         creds.Password,
		TenantID:         creds.ProjectId,
		DomainName:       creds.ProjectDomainName,
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate to OpenStack")
	}

	client, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Region: region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Neutron client")
	}

	tag := "openshiftClusterID=" + kc.ClusterId
	log.Printf("Using %s as resources tag", tag)

	log.Print("Ensuring services network")
	svcNetId, err := ensureOpenStackNetwork(client, "kuryr-service-network", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create service network")
	}
	log.Printf("Services network %s present", svcNetId)

	// Service subnet
	// We need last usable IP from this CIDR
	_, svcNet, err := net.ParseCIDR(conf.ServiceNetwork)
	// This will get us the last one (broadcast)
	ip := svcNet.IP
	mask := svcNet.Mask
	ip.Mask(mask)
	ip = net.IP{ip[0] | ^mask[0], ip[1] | ^mask[1], ip[2] | ^mask[2], ip[3] | ^mask[3]}
	// And this second to last (last usable)
	ip[3] &= 0xFE
	ipStr := ip.String()
	log.Printf("Ensuring services subnet with %s CIDR and %s gateway", conf.ServiceNetwork, ipStr)
	svcSubnetId, err := ensureOpenStackSubnet(client, "kuryr-service-subnet", tag,
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
	podSubnetpoolId, err := ensureOpenStackSubnetpool(client, "kuryr-pod-subnetpool", tag, cidrs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create pod subnetpool")
	}
	log.Printf("Pod subnetpool %s present", podSubnetpoolId)

	workerSubnetId, err := findOpenStackSubnetId(client, "nodes", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes subnet")
	}
	log.Printf("Found worker nodes subnet %s", workerSubnetId)
	routerId, err := findOpenStackRouterId(client, "openshift-external-router", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes router")
	}
	log.Printf("Found worker nodes router %s", routerId)
	ps, err := getOpenStackRouterPorts(client, routerId)
	if err != nil {
		return nil, errors.Wrap(err, "failed list ports of worker nodes router")
	}

	if !lookupOpenStackPort(ps, svcSubnetId) {
		log.Printf("Ensuring service subnet router port with %s IP", ipStr)
		portId, err := ensureOpenStackPort(client, "kuryr-service-subnet-router-port", tag,
			svcNetId, svcSubnetId, ipStr)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create service subnet router port")
		}
		log.Printf("Service subnet router port %s present, adding it as interface.", portId)
		err = ensureOpenStackRouterInterface(client, routerId, nil, &portId)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create service subnet router interface")
		}
	}

	masterSgId, err := findOpenStackSgId(client, "master", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find master nodes security group")
	}
	log.Printf("Found master nodes security group %s", masterSgId)
	workerSgId, err := findOpenStackSgId(client, "worker", tag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find worker nodes security group")
	}
	log.Printf("Found worker nodes security group %s", workerSgId)

	log.Print("Ensuring pods security group")
	podSgId, err := ensureOpenStackSg(client, "kuryr-pods-security-group", tag)
	log.Printf("Pods security group %s present", podSgId)

	log.Print("Allowing traffic from masters and nodes to pods")
	err = ensureOpenStackSgRule(client, podSgId, masterSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic from masters")
	}
	err = ensureOpenStackSgRule(client, podSgId, workerSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic from workers")
	}
	err = ensureOpenStackSgRule(client, masterSgId, podSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic to masters")
	}
	err = ensureOpenStackSgRule(client, workerSgId, podSgId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add rule opening traffic to workers")
	}
	log.Print("All requried traffic allowed")

	lbClient, err := openstack.NewLoadBalancerV2(provider, gophercloud.EndpointOpts{
		Region: region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Octavia client")
	}

	// We need first usable IP from services CIDR
	// This will get us the first one (subnet IP)
	ip = svcNet.IP
	// And this second one (first usable)
	ip[3] |= 0x01
	ipStr = ip.String()
	log.Printf("Creating OpenShift API loadbalancer with IP %s", ipStr)
	lbId, err := ensureOpenStackLb(lbClient, "kuryr-api-loadbalancer", ipStr, svcSubnetId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create OpenShift API loadbalancer")
	}
	log.Printf("OpenShift API loadbalancer %s present", lbId)

	log.Print("Creating OpenShift API loadbalancer pool")
	poolId, err := ensureOpenStackLbPool(lbClient, "kuryr-api-loadbalancer-pool", lbId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create OpenShift API loadbalancer pool")
	}
	log.Printf("OpenShift API loadbalancer pool %s present", poolId)

	log.Print("Creating OpenShift API loadbalancer listener")
	listenerId, err := ensureOpenStackLbListener(lbClient, "kuryr-api-loadbalancer-listener", lbId, poolId, 443)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create OpenShift API loadbalancer listener")
	}
	log.Printf("OpenShift API loadbalancer listener %s present", listenerId)

	// We need to list all master ports and add them to the LB pool
	log.Print("Creating OpenShift API loadbalancer pool members")
	r, _ := regexp.Compile("^master-port-[0-9]+$")
	portList, err := listOpenStackPortsMatchingPattern(client, tag, r)
	for _, port := range portList {
		if len(port.FixedIPs) > 0 {
			portIp := port.FixedIPs[0].IPAddress
			log.Printf("Found port %s with IP %s", port.ID, portIp)
			memberId, err := ensureOpenStackLbPoolMember(lbClient, port.Name, lbId,
				poolId, portIp, workerSubnetId, 6443)
			if err != nil {
				log.Printf("Failed to add port %s to LB pool %s: %s", port.ID, poolId, err)
				continue
			}
			log.Printf("Added member %s to LB pool %s", memberId, poolId)
		} else {
			log.Printf("Matching port %s has no IP", port.ID)
		}
	}

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

