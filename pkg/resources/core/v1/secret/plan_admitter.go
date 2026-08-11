package secret

import (
	"fmt"

	"github.com/rancher/rancher/pkg/plan"
	planv1alpha1 "github.com/rancher/rancher/pkg/plan/api/plan.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/generated/controllers/plan.cattle.io/v1alpha1"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

const machinePlanSecretType = "rke.cattle.io/machine-plan"

type planAdmitter struct {
	beaconClient v1alpha1.BeaconClient
}

// Admit validates plan Secrets at admission time.
func (p *planAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("secret planAdmitter Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
	}

	if secret.Type != machinePlanSecretType {
		return admission.ResponseAllowed(), nil
	}

	// prevented protected labels from being changed once set
	if request.Operation == admissionv1.Update {
		oldSecret, err := common.FromRequest[corev1.Secret](request.OldObject)
		if err != nil {
			return admission.ResponseBadRequest(fmt.Sprintf("invalid old object: %v", err)), nil
		}

		if oldSecret.Labels != nil {
			if l, ok := oldSecret.Labels[planv1alpha1.ClusterLifecycleNameLabel]; ok && (secret.Labels == nil || l != clusterName) {
				return admission.ResponseBadRequest(fmt.Sprintf("%s cannot be changed once set", planv1alpha1.ClusterLifecycleNameLabel)), nil
			}
			if l, ok := oldSecret.Labels[planv1alpha1.ClusterLifecycleGroupLabel]; ok && (secret.Labels == nil || l != secret.Labels[planv1alpha1.ClusterLifecycleGroupLabel]) {
				return admission.ResponseBadRequest(fmt.Sprintf("%s cannot be changed once set", planv1alpha1.ClusterLifecycleGroupLabel)), nil
			}
			if l, ok := oldSecret.Labels[planv1alpha1.ClusterLifecycleKindLabel]; ok && (secret.Labels == nil || l != secret.Labels[planv1alpha1.ClusterLifecycleKindLabel]) {
				return admission.ResponseBadRequest(fmt.Sprintf("%s cannot be changed once set", planv1alpha1.ClusterLifecycleKindLabel)), nil
			}
			if l, ok := oldSecret.Labels[planv1alpha1.MachineLifecycleNameLabel]; ok && (secret.Labels == nil || l != clusterName) {
				return admission.ResponseBadRequest(fmt.Sprintf("%s cannot be changed once set", planv1alpha1.MachineLifecycleNameLabel)), nil
			}
			if l, ok := oldSecret.Labels[planv1alpha1.MachineLifecycleGroupLabel]; ok && (secret.Labels == nil || l != secret.Labels[planv1alpha1.MachineLifecycleGroupLabel]) {
				return admission.ResponseBadRequest(fmt.Sprintf("%s cannot be changed once set", planv1alpha1.MachineLifecycleGroupLabel)), nil
			}
			if l, ok := oldSecret.Labels[planv1alpha1.MachineLifecycleKindLabel]; ok && (secret.Labels == nil || l != secret.Labels[planv1alpha1.MachineLifecycleKindLabel]) {
				return admission.ResponseBadRequest(fmt.Sprintf("%s cannot be changed once set", planv1alpha1.MachineLifecycleKindLabel)), nil
			}

		}
	}

	if secret.Labels != nil {
		// ensure beacon owner in update matches current beacon owner.
		owner, ok := secret.Labels[planv1alpha1.BeaconOwnerLabelKey]
		if !ok {
			return admission.ResponseAllowed(), nil
		}

		clusterName, ok := secret.Labels[planv1alpha1.ClusterLifecycleNameLabel]
		if !ok {
			return admission.ResponseAllowed(), nil
		}

		beacon, err := p.beaconClient.Get(secret.Namespace, clusterName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return admission.ResponseAllowed(), nil
		} else if err != nil {
			return admission.ResponseBadRequest(fmt.Sprintf("failed to get beacon client: %v", err)), nil
		}

		if owner != beacon.Status.Owner {
			return admission.ResponseBadRequest(fmt.Sprintf("not owned by %s", owner)), nil
		}

	}

	planData, ok := secret.Data["plan"]
	if !ok {
		return admission.ResponseAllowed(), nil
	}

	if _, err := plan.Parse(planData); err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("invalid plan: %v", err)), nil
	}

	return admission.ResponseAllowed(), nil
}
