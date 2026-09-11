"""CounselClear mail attachment adapter (M1 local prototype).

Public surface::

    from app.mail import (
        AdapterLimits, AdapterRequest, Envelope, MailAdapter,
        PolicyReference, TrustedCallerContext,
    )

The adapter is transport-agnostic: an SMTP listener, a queue consumer, or a
test harness builds an :class:`AdapterRequest` from bytes it received plus
the caller context it authenticated, and gets back an
:class:`AdapterResult`. Processors are injected; see ``app.mail.processor``.
"""

from .adapter import MailAdapter
from .contract import (
    AdapterLimits,
    AdapterRequest,
    AdapterResult,
    AttachmentOutcome,
    ContractError,
    Envelope,
    OutboundMessage,
    PolicyReference,
    TrustedCallerContext,
)
from .processor import (
    AttachmentProcessor,
    ProcessorUnavailable,
    ProcessRequest,
    ProcessResult,
)

__all__ = [
    "AdapterLimits",
    "AdapterRequest",
    "AdapterResult",
    "AttachmentOutcome",
    "AttachmentProcessor",
    "ContractError",
    "Envelope",
    "MailAdapter",
    "OutboundMessage",
    "PolicyReference",
    "ProcessRequest",
    "ProcessResult",
    "ProcessorUnavailable",
    "TrustedCallerContext",
]
