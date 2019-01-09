package networkconfig

import (
	"context"
	"log"
	"time"

	"github.com/pkg/errors"

	networkoperatorv1 "github.com/openshift/cluster-network-operator/pkg/apis/networkoperator/v1"
	"github.com/openshift/cluster-network-operator/pkg/apply"
	"github.com/openshift/cluster-network-operator/pkg/network"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	uns "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Configuration objects must have a single name
const CONFIG_OBJECT_NAME = "default"

// The periodic resync interval.
// We will re-run the reconciliation logic, even if the network configuration
// hasn't changed.
var ResyncPeriod = 5 * time.Minute

// ManifestPaths is the path to the manifest templates
// bad, but there's no way to pass configuration to the reconciler right now
var ManifestPath = "./bindata"

// Add creates a new NetworkConfig Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileNetworkConfig{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("networkconfig-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource NetworkConfig
	err = c.Watch(&source.Kind{Type: &networkoperatorv1.NetworkConfig{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileNetworkConfig{}

// ReconcileNetworkConfig reconciles a NetworkConfig object
type ReconcileNetworkConfig struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a NetworkConfig object and makes changes based on the state read
// and what is in the NetworkConfig.Spec
//
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileNetworkConfig) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	log.Printf("Reconciling NetworkConfig %s/%s\n", request.Namespace, request.Name)

	// We won't create more than one network
	if request.Name != CONFIG_OBJECT_NAME {
		log.Printf("Ignoring NetworkConfig without default name")
		return reconcile.Result{}, nil
	}

	// Fetch the NetworkConfig instance
	instance := &networkoperatorv1.NetworkConfig{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Printf("Unable to retrieve NetworkConfig object: %v", err)
		return reconcile.Result{}, err
	}

	// Validate the configuration
	if err := network.Validate(&instance.Spec); err != nil {
		log.Printf("Failed to validate NetworkConfig.Spec: %v", err)
		return reconcile.Result{}, err
	}

	// Retrieve the previously applied configuration
	prev, err := GetAppliedConfiguration(context.TODO(), r.client, instance.ObjectMeta.Name)
	if err != nil {
		log.Printf("Failed to retrieve previously applied configuration: %v", err)
		return reconcile.Result{}, err
	}

	// Fill all defaults explicitly
	network.FillDefaults(&instance.Spec, prev)

	// Compare against previous applied configuration to see if this change
	// is safe.
	if prev != nil {
		// We may need to fill defaults here -- sort of as a poor-man's
		// upconversion scheme -- if we add additional fields to the config.
		err = network.IsChangeSafe(prev, &instance.Spec)
		if err != nil {
			log.Printf("Not applying unsafe change: %v", err)
			return reconcile.Result{},
				errors.Wrapf(err, "not applying unsafe change")
		}
	}

	// Bootstrap any resources
	bootstrapData, err := network.Bootstrap(&instance.Spec)
	if err != nil {
		log.Printf("Failed to bootstrap: %v", err)
		return reconcile.Result{}, errors.Wrapf(err, "failed to bootstrap")
	}

	// Generate the objects
	objs, err := network.Render(&instance.Spec, *bootstrapData, ManifestPath)
	if err != nil {
		log.Printf("Failed to render: %v", err)
		return reconcile.Result{}, errors.Wrapf(err, "failed to render")
	}

	// The first object we create should be the record of our applied configuration
	app, err := AppliedConfiguration(instance)
	if err != nil {
		log.Printf("Failed to render applied: %v", err)
		return reconcile.Result{}, errors.Wrapf(err, "failed to render applied")
	}
	objs = append([]*uns.Unstructured{app}, objs...)

	// Apply the objects to the cluster
	for _, obj := range objs {
		if err := controllerutil.SetControllerReference(instance, obj, r.scheme); err != nil {
			err = errors.Wrapf(err, "could not set reference for (%s) %s/%s", obj.GroupVersionKind(), obj.GetNamespace(), obj.GetName())
			log.Println(err)
			return reconcile.Result{}, err
		}

		// Open question: should an error here indicate we will never retry?
		if err := apply.ApplyObject(context.TODO(), r.client, obj); err != nil {
			err = errors.Wrapf(err, "could not apply (%s) %s/%s", obj.GroupVersionKind(), obj.GetNamespace(), obj.GetName())
			log.Println(err)
			return reconcile.Result{}, err
		}
	}

	log.Printf("all objects successfully applied")

	// All was successful. Request that this be re-triggered after ResyncPeriod,
	// so we can reconcile state again.
	return reconcile.Result{RequeueAfter: ResyncPeriod}, nil
}
