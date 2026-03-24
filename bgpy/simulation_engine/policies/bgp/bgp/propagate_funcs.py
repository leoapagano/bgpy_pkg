from collections.abc import Mapping
from typing import Any, Protocol

from bgpy.shared.enums import Relationships


class AnnLike(Protocol):
    prefix: str
    as_path: tuple[int, ...]
    next_hop_asn: int
    seed_asn: int | None
    recv_relationship: Relationships

    @property
    def origin(self) -> int: ...

    def copy(
        self, overwrite_default_kwargs: dict[Any, Any] | None = None
    ) -> "AnnLike": ...


class PolicyReceiver(Protocol):
    def receive_ann(self, ann: AnnLike) -> None: ...


class ASLike(Protocol):
    asn: int
    peers: tuple["ASLike", ...]
    providers: tuple["ASLike", ...]
    customers: tuple["ASLike", ...]
    policy: PolicyReceiver


class BGPPropagateLike(Protocol):
    as_: ASLike
    local_rib: Mapping[str, AnnLike]

    def _prev_sent(self, neighbor: ASLike, ann: AnnLike) -> bool: ...

    def _policy_propagate(
        self,
        neighbor: ASLike,
        ann: AnnLike,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> bool: ...

    def _process_outgoing_ann(
        self,
        neighbor: ASLike,
        ann: AnnLike,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> None: ...


def propagate_to_providers(self) -> None:
    """Propogates to providers

    Propogate ann's that have a recv_rel of origin or customer to providers
    """

    send_rels: set[Relationships] = {
        Relationships.ORIGIN,
        Relationships.CUSTOMERS,
    }
    self._propagate(Relationships.PROVIDERS, send_rels)


def propagate_to_customers(self) -> None:
    """Propogates to customers"""

    # Anns that have any of these as recv_rel get propogated
    send_rels: set[Relationships] = {
        Relationships.ORIGIN,
        Relationships.CUSTOMERS,
        Relationships.PEERS,
        Relationships.PROVIDERS,
    }
    self._propagate(Relationships.CUSTOMERS, send_rels)


def propagate_to_peers(self) -> None:
    """Propogates to peers"""

    # Anns that have any of these as recv_rel get propogated
    send_rels: set[Relationships] = {
        Relationships.ORIGIN,
        Relationships.CUSTOMERS,
    }
    self._propagate(Relationships.PEERS, send_rels)


def _propagate(
    self: BGPPropagateLike,
    propagate_to: Relationships,
    send_rels: set[Relationships],
) -> None:
    """Propogates announcements from local rib to other ASes

    send_rels is the relationships that are acceptable to send
    """

    if propagate_to.value == Relationships.PROVIDERS.value:
        neighbors = self.as_.providers
    elif propagate_to.value == Relationships.PEERS.value:
        neighbors = self.as_.peers
    elif propagate_to.value == Relationships.CUSTOMERS.value:
        neighbors = self.as_.customers
    else:
        raise NotImplementedError

    for _prefix, unprocessed_ann in self.local_rib.items():
        # Starting in v4 we must set the next_hop when sending
        # Copying announcements is a bottleneck for sims,
        # so we try to do this as little as possible
        if neighbors and unprocessed_ann.recv_relationship in send_rels:
            ann = unprocessed_ann.copy({"next_hop_asn": self.as_.asn})
        else:
            continue

        for neighbor in neighbors:
            if ann.recv_relationship in send_rels and not self._prev_sent(
                neighbor, ann
            ):
                # Policy took care of it's own propagation for this ann
                if self._policy_propagate(neighbor, ann, propagate_to, send_rels):
                    continue
                else:
                    self._process_outgoing_ann(neighbor, ann, propagate_to, send_rels)


def _policy_propagate(
    self: BGPPropagateLike,
    neighbor: ASLike,
    ann: AnnLike,
    propagate_to: Relationships,
    send_rels: set[Relationships],
) -> bool:
    """Custom policy propagation that can be overriden"""

    return False


def _prev_sent(self: BGPPropagateLike, neighbor: ASLike, ann: AnnLike) -> bool:
    """Don't resend anything for BGPAS. For this class it doesn't matter"""
    return False


def _process_outgoing_ann(
    self: BGPPropagateLike,
    neighbor: ASLike,
    ann: AnnLike,
    propagate_to: Relationships,
    send_rels: set[Relationships],
) -> None:
    """Adds ann to the neighbors recv q"""

    # Add the new ann to the incoming anns for that prefix
    neighbor.policy.receive_ann(ann)
