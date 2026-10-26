"""CyberShield Enterprise Security Platform.

A defensive security automation platform: host auditing, authorised network
discovery, vulnerability analysis, passive traffic monitoring, compliance
mapping, alerting and reporting.

CyberShield performs **defensive and authorised** tasks only. Active scanning is
restricted to an explicit allow-list of networks (see ``CYBERSHIELD_ALLOWED_TARGETS``)
and every action is recorded in a tamper-evident audit trail.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
