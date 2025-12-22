"""
DOM XSS Trigger Strategies - Model-Guided Random Walk Strategy
Strategie 2: State-Independent Model für intelligente Priorisierung

Basiert auf: "Improving Behavioral Program Analysis with Environment Models"
"""
import random
import logging
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field

from .base_strategy import BaseStrategy, ActionCandidate, ActionResult

logger = logging.getLogger(__name__)


@dataclass
class StateIndependentModel:
    """
    State-Independent Model (E, λ)
    
    E: Menge aller beobachteten Action Candidates
    λ(c, c'): Wahrscheinlichkeit dass c' nach c verfügbar ist
    """
    w_model: float = 25.0
    
    all_candidates: Set[str] = field(default_factory=set)
    executed_candidates: Set[str] = field(default_factory=set)
    successor_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    observation_counts: Dict[str, int] = field(default_factory=dict)
    
    def observe_candidates(self, candidate_ids: List[str]):
        """Registriert beobachtete Candidates"""
        for c_id in candidate_ids:
            self.all_candidates.add(c_id)
            self.observation_counts[c_id] = self.observation_counts.get(c_id, 0) + 1
    
    def record_execution(self, executed_id: str, successor_ids: List[str]):
        """Registriert Ausführung und Nachfolger"""
        self.executed_candidates.add(executed_id)
        
        if executed_id not in self.successor_counts:
            self.successor_counts[executed_id] = {}
        
        for succ_id in successor_ids:
            self.successor_counts[executed_id][succ_id] = \
                self.successor_counts[executed_id].get(succ_id, 0) + 1
    
    def get_lambda(self, c: str, c_prime: str) -> float:
        """λ(c, c'): P(c' verfügbar | c ausgeführt)"""
        if c not in self.successor_counts or c_prime not in self.successor_counts[c]:
            return 0.0
        
        total = self.observation_counts.get(c, 1)
        count = self.successor_counts[c][c_prime]
        return min(1.0, count / total)
    
    def get_successors(self, c: str) -> Set[str]:
        """Alle Nachfolger von c"""
        return set(self.successor_counts.get(c, {}).keys())
    
    def calculate_ratio(self, c: str) -> float:
        """rc: Anteil nicht-ausgeführter Nachfolger"""
        successors = self.get_successors(c)
        if not successors:
            return 0.0
        
        unexecuted_sum = sum(
            self.get_lambda(c, c_prime)
            for c_prime in successors
            if c_prime not in self.executed_candidates
        )
        return unexecuted_sum / len(successors)
    
    def calculate_weight(self, c: str, base_weight: float = 1.0) -> float:
        """Finales Gewicht: wc = w_base * (1 + rc * w_model)"""
        rc = self.calculate_ratio(c)
        return base_weight * (1 + rc * self.w_model)
    
    def get_stats(self) -> Dict:
        """Statistiken"""
        return {
            'total_candidates': len(self.all_candidates),
            'executed_candidates': len(self.executed_candidates),
            'execution_rate': len(self.executed_candidates) / max(1, len(self.all_candidates)),
            'total_transitions': sum(sum(c.values()) for c in self.successor_counts.values())
        }


class ModelGuidedStrategy(BaseStrategy):
    """
    Model-Guided Random Walk.
    
    Priorisiert Aktionen die zu vielen noch nicht
    ausgeführten Nachfolge-Aktionen führen.
    """
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.w_model = self.config.get('w_model', 25.0)
        self.exploration_bonus = self.config.get('exploration_bonus', 2.0)
        self.model = StateIndependentModel(w_model=self.w_model)
        
        # XSS-Priorisierung
        self.input_weight_boost = 1.5
        self.form_weight_boost = 2.0
        
    @property
    def name(self) -> str:
        return "Model-Guided"
    
    def _get_base_weight(self, candidate: ActionCandidate) -> float:
        """Basis-Gewicht basierend auf XSS-Relevanz"""
        weight = 1.0
        
        if candidate.has_input:
            weight *= self.input_weight_boost
        if candidate.is_form:
            weight *= self.form_weight_boost
        if candidate.has_event_handler:
            weight *= 1.3
        if candidate.id not in self.executed_candidates:
            weight *= self.exploration_bonus
        
        return weight
    
    async def select_next_action(
        self, 
        candidates: List[ActionCandidate]
    ) -> Optional[ActionCandidate]:
        """Wählt Candidate basierend auf Model-Gewichten"""
        if not candidates:
            return None
        
        # Registriere im Model
        candidate_ids = [c.id for c in candidates]
        self.model.observe_candidates(candidate_ids)
        
        # Berechne Gewichte
        weights = []
        for candidate in candidates:
            base_weight = self._get_base_weight(candidate)
            
            if candidate.id in self.model.executed_candidates:
                final_weight = self.model.calculate_weight(candidate.id, base_weight)
            else:
                final_weight = base_weight * self.exploration_bonus
            
            weights.append(final_weight)
        
        # Weighted Random Choice
        total_weight = sum(weights)
        if total_weight == 0:
            return random.choice(candidates)
        
        pick = random.uniform(0, total_weight)
        current = 0
        
        for candidate, weight in zip(candidates, weights):
            current += weight
            if current >= pick:
                logger.debug(f"[Model-Guided] {candidate.text[:30]} (w={weight:.2f})")
                return candidate
        
        return candidates[-1]
    
    async def on_action_completed(
        self, 
        action: ActionCandidate, 
        result: ActionResult,
        new_candidates: List[ActionCandidate]
    ):
        """Update Model"""
        successor_ids = [c.id for c in new_candidates]
        self.model.record_execution(action.id, successor_ids)
        
        stats = self.model.get_stats()
        logger.debug(f"[Model] {stats['executed_candidates']}/{stats['total_candidates']} executed")
    
    def get_model_stats(self) -> Dict:
        """Model-Statistiken für Reports"""
        return self.model.get_stats()
