"""Phase 7 advisory ML surface.

This platform ships no trained model.  The only legitimate "machine layer" here
is a deterministic advisory that explains *coverage gaps* from persisted scan
state -- never a prediction, never a confidence score, never an upgrade to
evidence.  Rows are recorded in ``ml_inferences`` with ``status=advisory_only``
and ``model_name=None`` so it is impossible to confuse the advisory with an AI
finding.
"""
from app.ml.advisory import generate

__all__ = ["generate"]