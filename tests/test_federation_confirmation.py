"""
Activity is not identity. Observing a resource being used in two clusters says both are
busy; it says nothing about the two being the same trust principal.

`_observed_in()` matched on NAME alone -- no kind, no namespace -- and two runtime
observations promoted a shared identity from `candidate` to `confirmed`. On a live
dual-cluster run that produced this, and it is wrong in the most ordinary way possible:

    CONFIRMED  Role/falco/falco
               clusters=[<an EKS cluster>, docker-desktop]
               verification=runtime evidence names this resource in both

Both clusters had Falco installed from the same Helm chart, so each had a Role named
`falco`, a DaemonSet named `falco`, and pods named `falco-xxxxx`. Reading a file inside
each cluster's own Falco pod was enough. Two independent installs of the same chart are
not one principal and there is no path from either cluster to the other -- exactly the
"same Helm chart" false positive the federation work exists to prevent.

Two things were wrong:

1. A Kubernetes Role, RoleBinding, ServiceAccount, Secret, ConfigMap, ClusterRole or
   ClusterRoleBinding is cluster-local by construction. `cluster-admin` exists in every
   cluster on earth and is not shared. No amount of observed activity can make two of
   them one principal, so these kinds can never be confirmed this way -- only a principal
   that genuinely lives OUTSIDE the cluster (a cloud IAM role, a managed identity) can.

2. Even for those kinds, name-only matching let a Pod's activity vouch for a Role.

Confirmation now needs an externally-owned principal AND observation on both sides.
Everything else stays `candidate`, which is what a name collision actually is.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8smatrixwarden.core import federation as F


def test_kubernetes_local_kinds_are_never_confirmable_by_activity():
    for kind in ("Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding",
                 "ServiceAccount", "Secret", "ConfigMap"):
        assert kind not in F._CROSS_CLUSTER_PRINCIPAL_KINDS, (
            f"{kind} is cluster-local; observed activity cannot make two of them "
            f"one trust principal")


def test_an_externally_owned_principal_stays_confirmable():
    """The tier must not be deleted outright -- a cloud IAM role really can be one
    principal two clusters both assume."""
    assert F._CROSS_CLUSTER_PRINCIPAL_KINDS, (
        "confirmation was removed entirely; a genuinely shared cloud principal can no "
        "longer be reported, which suppresses real findings")
    for kind in F._CROSS_CLUSTER_PRINCIPAL_KINDS:
        assert kind in F._IDENTITY_KINDS


def test_the_live_falco_false_positive_cannot_recur():
    """The exact shape observed: same-named Role in two clusters, runtime activity in
    both, nothing linking them."""
    assert not F._confirmable("Role", {"a", "b"}, verified_sides=True)
    assert not F._confirmable("ClusterRole", {"a", "b"}, verified_sides=True)
    assert F._confirmable("CloudIAM", {"a", "b"}, verified_sides=True)


def test_confirmation_still_needs_both_sides_identified_and_observed():
    assert not F._confirmable("CloudIAM", {"a"}, verified_sides=True), "one side only"
    assert not F._confirmable("CloudIAM", {"a", "b"}, verified_sides=False), (
        "an unidentified endpoint cannot anchor a confirmed path")


def test_a_withheld_confirmation_says_why():
    """A candidate that WOULD have been confirmed must explain itself, or the operator
    reads the downgrade as the tool having found nothing."""
    text = F._verification_text("Role", observed={"a", "b"}, verified_sides=True,
                                confirmed=False)
    assert "cluster-local" in text or "same principal" in text, text
