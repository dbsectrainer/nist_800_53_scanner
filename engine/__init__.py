"""Evidence-driven assessment engine (collect -> evaluate -> prove).

Collectors gather read-only evidence; the evaluator applies versioned
policy-as-code rules to that evidence. Missing, stale or unreachable
evidence yields ``not_assessed`` and is never reported as a pass.
"""

from .models import Assessment, AssessmentRun, Evidence, Method, Status

__all__ = ["Assessment", "AssessmentRun", "Evidence", "Method", "Status"]
