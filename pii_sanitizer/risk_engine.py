"""
VAULT Aegis — PII Sanitizer: Risk Scoring Engine
===================================================
Evaluates aggregate risk from PII detections and generates
structured risk scores, alert payloads, and blocking decisions.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from .config import RiskLevel, RISK_SCORE_MAP, BLOCK_THRESHOLD, PII_TYPES
from .detector import PIIDetection


# ──────────────────────────────────────────────────────────────────────────────
# Risk Score Result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PIIRiskScore:
    """Aggregate risk score from all PII detections."""
    level: RiskLevel
    score: int              # 0–100
    summary: str
    detections_count: int
    dominant_type: Optional[str]  # PII type with highest risk

    def as_dict(self) -> dict:
        return {
            "level": self.level.value,
            "score": self.score,
            "summary": self.summary,
            "detections_count": self.detections_count,
            "dominant_type": self.dominant_type,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Risk Engine
# ──────────────────────────────────────────────────────────────────────────────

class PIIRiskEngine:
    """
    Scores aggregate risk from PII detections.

    Scoring algorithm:
      - Base score = highest risk level among detections
      - Bonus +5 per additional detection (capped at 100)
      - Confidence-weighted average adjusts final score

    Usage:
        engine = PIIRiskEngine()
        score = engine.score(detections, source="api_gateway")
        if engine.should_block(score):
            raise Exception("PII risk too high")
    """

    def __init__(self, block_threshold: int = BLOCK_THRESHOLD):
        self.block_threshold = block_threshold

    def score(
        self,
        detections: List[PIIDetection],
        source: str = "unknown",
    ) -> PIIRiskScore:
        """
        Compute aggregate risk score from a list of PII detections.

        Args:
            detections: List of PII detections from the detector.
            source: Source identifier (api_gateway, ai_pipeline, scanner, log).

        Returns:
            PIIRiskScore with level, numeric score, summary, and dominant type.
        """
        if not detections:
            return PIIRiskScore(
                level=RiskLevel.LOW,
                score=0,
                summary="No PII detected",
                detections_count=0,
                dominant_type=None,
            )

        # Find the highest risk detection
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        max_risk = RiskLevel.LOW
        dominant_type = detections[0].pii_type

        for det in detections:
            if risk_order.index(det.risk_level) > risk_order.index(max_risk):
                max_risk = det.risk_level
                dominant_type = det.pii_type

        # Base score from highest risk level
        base_score = RISK_SCORE_MAP.get(max_risk, 25)

        # Add penalty for multiple detections (+5 each, capped)
        multi_penalty = min((len(detections) - 1) * 5, 20)
        raw_score = min(base_score + multi_penalty, 100)

        # Confidence-weighted adjustment
        avg_confidence = sum(d.confidence for d in detections) / len(detections)
        final_score = int(raw_score * avg_confidence)
        final_score = max(1, min(final_score, 100))

        # Determine final risk level
        if final_score >= RISK_SCORE_MAP[RiskLevel.CRITICAL]:
            final_level = RiskLevel.CRITICAL
        elif final_score >= RISK_SCORE_MAP[RiskLevel.HIGH]:
            final_level = RiskLevel.HIGH
        elif final_score >= RISK_SCORE_MAP[RiskLevel.MEDIUM]:
            final_level = RiskLevel.MEDIUM
        else:
            final_level = RiskLevel.LOW

        # Build summary
        type_counts = {}
        for det in detections:
            info = PII_TYPES.get(det.pii_type, {})
            label = info.get("label", det.pii_type)
            type_counts[label] = type_counts.get(label, 0) + 1

        summary_parts = [f"{count}x {label}" for label, count in type_counts.items()]
        summary = (
            f"{len(detections)} PII detection(s) from {source}: "
            + ", ".join(summary_parts)
            + f". Risk: {final_level.value} ({final_score}/100)"
        )

        return PIIRiskScore(
            level=final_level,
            score=final_score,
            summary=summary,
            detections_count=len(detections),
            dominant_type=dominant_type,
        )

    def should_block(self, risk_score: PIIRiskScore) -> bool:
        """
        Determine if the request should be blocked based on risk score.

        Returns:
            True if the score meets or exceeds the block threshold.
        """
        return risk_score.score >= self.block_threshold

    def to_alert(
        self,
        risk_score: PIIRiskScore,
        source: str = "unknown",
        detections: Optional[List[PIIDetection]] = None,
    ) -> Dict[str, Any]:
        """
        Generate an alert payload for the VAULT Threat Detection Engine.

        Args:
            risk_score: The computed risk score.
            source: Source of the detection.
            detections: Optional list of detections for detail.

        Returns:
            Alert dict suitable for logging or notification.
        """
        alert = {
            "alert_type": "PII_DETECTION",
            "risk_level": risk_score.level.value,
            "risk_score": risk_score.score,
            "detections_count": risk_score.detections_count,
            "dominant_type": risk_score.dominant_type,
            "source": source,
            "summary": risk_score.summary,
            "should_block": self.should_block(risk_score),
        }

        if detections:
            alert["details"] = [
                {
                    "type": d.pii_type,
                    "label": d.label,
                    "confidence": d.confidence,
                    "risk_level": d.risk_level.value,
                    "category": d.category.value,
                }
                for d in detections
            ]

        return alert
