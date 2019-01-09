package network

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pkg/errors"

	uns "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	netv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"
	"github.com/openshift/cluster-network-operator/pkg/render"
)

// renderKuryr returns manifests for Kuryr SDN.
// This creates
// - the ClusterNetwork object
// - the kuryr namespace
// - the kuryr-controller deployment
// - the kuryr-daemon daemonset
// and some other small things.
func renderKuryr(conf *netv1.NetworkConfigSpec, bootstrapData BootstrapData,
	manifestDir string) ([]*uns.Unstructured, error) {
	c := conf.DefaultNetwork.KuryrConfig

	objs := []*uns.Unstructured{}

	// render the manifests on disk
	data := render.MakeRenderData()

	// OpenStack credentials
	data.Data["OpenStackCACertificate"] = c.OpenStackCACertificate
	data.Data["OpenStackAuthURL"] = c.OpenStackCredentials.AuthURL
	data.Data["OpenStackPassword"] = c.OpenStackCredentials.Password
	data.Data["OpenStackProjectDomainName"] = c.OpenStackCredentials.ProjectDomainName
	data.Data["OpenStackProjectId"] = c.OpenStackCredentials.ProjectId
	data.Data["OpenStackUserDomainName"] = c.OpenStackCredentials.UserDomainName
	data.Data["OpenStackUsername"] = c.OpenStackCredentials.Username
	data.Data["KuryrProject"] = c.OpenStackCredentials.ProjectId

	data.Data["PodSecurityGroups"] = strings.Join(bootstrapData.Kuryr.PodSecurityGroups, ",")
	data.Data["WorkerNodesSubnet"] = bootstrapData.Kuryr.WorkerNodesSubnet
	data.Data["WorkerNodesRouter"] = bootstrapData.Kuryr.WorkerNodesRouter
	data.Data["PodSubnetpool"] = bootstrapData.Kuryr.PodSubnetpool
	data.Data["ServiceSubnet"] = bootstrapData.Kuryr.ServiceSubnet

	// kuryr-daemon DaemonSet data
	// TODO(dulek): Disable for Queens Kuryr if we'll be able to detect it.
	data.Data["DaemonEnableProbes"] = true
	data.Data["DaemonProbesPort"] = c.DaemonProbesPort

	// kuryr-controller Deployment data
	data.Data["ControllerEnableProbes"] = true
	data.Data["ControllerProbesPort"] = c.ControllerProbesPort

	data.Data["NodeImage"] = os.Getenv("NODE_IMAGE")
	data.Data["DaemonImage"] = os.Getenv("KURYR_DAEMON_IMAGE")
	data.Data["ControllerImage"] = os.Getenv("KURYR_CONTROLLER_IMAGE")

	manifests, err := render.RenderDir(filepath.Join(manifestDir, "network/kuryr"), &data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to render manifests")
	}

	objs = append(objs, manifests...)
	return objs, nil
}

// validateKuryr checks that the Kuryr specific configuration is basically sane.
func validateKuryr(conf *netv1.NetworkConfigSpec) []error {
	out := []error{}
	kc := conf.DefaultNetwork.KuryrConfig
	if kc == nil {
		out = append(out, errors.Errorf("KuryrConfig cannot be nil"))
		return out
	}
	osc := conf.DefaultNetwork.KuryrConfig.OpenStackCredentials

	// TODO(dulek): We should be able to drop this constraint when running
	//              with namespace isolation and subnetpools.
	if len(conf.ClusterNetworks) > 1 {
		out = append(out, errors.Errorf("Kuryr supports only one clusterNetwork element"))
	}

	// TODO(dulek): We'll need to extend those checks once we have support for
	//              keys and other methods of authentication.
	if len(osc.AuthURL) == 0 {
		out = append(out, errors.Errorf("OpenStackCredentials.AuthURL cannot be empty"))
	}

	if len(osc.Username) == 0 {
		out = append(out, errors.Errorf("OpenStackCredentials.Username cannot be empty"))
	}

	if len(osc.Password) == 0 {
		out = append(out, errors.Errorf("OpenStackCredentials.Password cannot be empty"))
	}

	if len(osc.ProjectDomainName) == 0 {
		out = append(out, errors.Errorf("OpenStackCredentials.ProjectDomainName cannot be empty"))
	}

	if len(osc.UserDomainName) == 0 {
		out = append(out, errors.Errorf("OpenStackCredentials.UserDomainName cannot be empty"))
	}

	if len(osc.ProjectId) == 0 {
		out = append(out, errors.Errorf("OpenStackCredentials.ProjectId cannot be empty"))
	}

	return out
}

// isKuryrChangeSafe currently returns an error if any changes are made.
// In the future we'll support changing some stuff.
func isKuryrChangeSafe(prev, next *netv1.NetworkConfigSpec) []error {
	pn := prev.DefaultNetwork.KuryrConfig
	nn := next.DefaultNetwork.KuryrConfig

	if reflect.DeepEqual(pn, nn) {
		return []error{}
	}
	return []error{errors.Errorf("cannot change kuryr configuration")}
}

func fillKuryrDefaults(conf *netv1.NetworkConfigSpec) {
	kc := conf.DefaultNetwork.KuryrConfig

	if kc.DaemonProbesPort == nil {
		var port uint16 = 8090
		kc.DaemonProbesPort = &port
	}

	if kc.ControllerProbesPort == nil {
		var port uint16 = 8082
		kc.ControllerProbesPort = &port
	}

	if len(kc.PodSecurityGroups) == 0 {
		kc.PodSecurityGroups = []string{"default"}
	}
}
