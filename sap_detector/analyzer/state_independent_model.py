"""
SPA Detection Tool - State-Independent Model
Basiert auf: "Improving Behavioral Program Analysis with Environment Models"
https://link.springer.com/chapter/10.1007/978-3-031-49187-0_9

Modell: (E, λ)
- E: Menge aller beobachteten Action Candidates
- λ(c, c'): Wahrscheinlichkeit dass c' nach c verfügbar ist
"""
import logging
from typing import Dict, Set

logger = logging.getLogger(__name__)


class StateIndependentModel:
    """
    State-Independent Model für Model-Guided Random Walk
    
    Das Modell kodiert Beziehungen zwischen Action Candidates der Form:
    "Wenn du A machst, dann kannst du B machen"
    
    Dies ist unabhängig vom State in dem A ausgeführt wird.
    """
    
    def __init__(self, w_model: float = 25.0):
        """
        Initialisiert das State-Independent Model
        
        Args:
            w_model: Gewichtungsparameter (default: 25 aus Paper)
        """
        self.w_model = w_model
        
        # E: Alle beobachteten Candidates
        self.all_candidates: Set[str] = set()
        
        # Bereits ausgeführte Candidates
        self.executed_candidates: Set[str] = set()
        
        # λ(c, c'): Nachfolger-Wahrscheinlichkeiten
        # candidate_successors[c][c'] = Anzahl wie oft c' nach c beobachtet wurde
        self.candidate_successors: Dict[str, Dict[str, int]] = {}
        
        # Wie oft wurde jeder Candidate insgesamt beobachtet
        self.candidate_observations: Dict[str, int] = {}
        
        logger.debug(f"State-Independent Model initialisiert (w_model={w_model})")
    
    def observe_candidates(self, candidates: list):
        """
        Registriert beobachtete Candidates im aktuellen State
        
        Args:
            candidates: Liste von Candidate-IDs
        """
        for c in candidates:
            self.all_candidates.add(c)
            self.candidate_observations[c] = self.candidate_observations.get(c, 0) + 1
    
    def execute_candidate(self, executed: str, successors: list):
        """
        Registriert Ausführung eines Candidates und dessen Nachfolger
        
        Args:
            executed: Der ausgeführte Candidate
            successors: Nach der Ausführung verfügbare Candidates
        """
        # Markiere als ausgeführt
        self.executed_candidates.add(executed)
        
        # Initialisiere Nachfolger-Dict falls nötig
        if executed not in self.candidate_successors:
            self.candidate_successors[executed] = {}
        
        # Update Nachfolger-Counts
        for succ in successors:
            self.candidate_successors[executed][succ] = \
                self.candidate_successors[executed].get(succ, 0) + 1
        
        logger.debug(f"Model-Update: {executed[:30]}... → {len(successors)} Nachfolger")
    
    def get_lambda(self, c: str, c_prime: str) -> float:
        """
        Berechnet λ(c, c'): Wahrscheinlichkeit dass c' nach c verfügbar ist
        
        Args:
            c: Ausgeführter Candidate
            c_prime: Nachfolger-Candidate
            
        Returns:
            Wahrscheinlichkeit im Bereich [0, 1]
        """
        if c not in self.candidate_successors:
            return 0.0
        
        succ_dict = self.candidate_successors[c]
        
        if c_prime not in succ_dict:
            return 0.0
        
        # P(c' | c) = count(c → c') / count(c executed)
        # Approximation: Nutze Observations als Nenner
        total_observations = self.candidate_observations.get(c, 1)
        successor_count = succ_dict[c_prime]
        
        return min(1.0, successor_count / total_observations)
    
    def get_successor_candidates(self, c: str) -> Set[str]:
        """
        Gibt Menge Sc zurück: Alle Nachfolger von c mit λ(c, c') > 0
        
        Args:
            c: Candidate-ID
            
        Returns:
            Menge aller Nachfolger-Candidates
        """
        if c not in self.candidate_successors:
            return set()
        
        return set(self.candidate_successors[c].keys())
    
    def calculate_ratio(self, c: str) -> float:
        """
        Berechnet rc: Ratio nicht-ausgeführter Nachfolger
        
        Formel aus Paper:
        rc = Σ λ(c, c') für alle nicht-ausgeführten c' / |Sc|
        
        Args:
            c: Candidate-ID
            
        Returns:
            Ratio im Bereich [0, 1]
        """
        successors = self.get_successor_candidates(c)
        
        if len(successors) == 0:
            return 0.0
        
        # Summe der Wahrscheinlichkeiten für nicht-ausgeführte Nachfolger
        sum_unexecuted = 0.0
        for c_prime in successors:
            if c_prime not in self.executed_candidates:
                sum_unexecuted += self.get_lambda(c, c_prime)
        
        # Ratio berechnen
        ratio = sum_unexecuted / len(successors)
        
        return ratio
    
    def calculate_weight(self, c: str, base_weight: float = 1.0) -> float:
        """
        Berechnet finales Gewicht für Candidate c
        
        Formel aus Paper (Gleichung 1):
        wc = w_random_walk * (1 + rc * w_model)
        
        Args:
            c: Candidate identifier
            base_weight: Basis-Gewicht von Random-Walk-Heuristics
            
        Returns:
            Finales Gewicht
        """
        rc = self.calculate_ratio(c)
        weight = base_weight * (1 + rc * self.w_model)
        
        logger.debug(f"Gewicht für {c[:30]}...: base={base_weight:.2f}, rc={rc:.3f}, final={weight:.2f}")
        
        return weight
    
    def get_stats(self) -> Dict:
        """
        Gibt Statistiken über das Modell zurück
        
        Returns:
            Dictionary mit Statistiken
        """
        total_candidates = len(self.all_candidates)
        executed_count = len(self.executed_candidates)
        
        avg_successors = 0.0
        if len(self.candidate_successors) > 0:
            avg_successors = sum(len(succ) for succ in self.candidate_successors.values()) / \
                           len(self.candidate_successors)
        
        return {
            'total_candidates': total_candidates,
            'executed_candidates': executed_count,
            'execution_rate': executed_count / max(1, total_candidates),
            'avg_successors': avg_successors,
            'total_observations': sum(self.candidate_observations.values())
        }