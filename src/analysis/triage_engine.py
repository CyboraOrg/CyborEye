# src/analysis/triage_engine.py
import yaml
import re
import glob
from typing import List, Dict, Any, Optional

class SmartTriageEngine:
    """
    A rule-based detection engine that processes normalized log events
    and generates ATT&CK-mapped findings, as described in the architecture.
    """

    def __init__(self, rules_directory: str = 'src/rules/triage'):
        """
        Initializes the engine by loading and compiling detection rules from YAML files.
        
        :param rules_directory: The directory containing YAML rule files.
        """
        self.rules = self._load_rules_from_directory(rules_directory)
        print(f"[TriageEngine] Loaded and compiled {len(self.rules)} rules successfully.")

    def _load_rules_from_directory(self, rules_directory: str) -> List[Dict[str, Any]]:
        """Loads and parses all YAML rule files from a given directory."""
        loaded_rules = []
        rule_paths = glob.glob(f"{rules_directory}/*.yml")
        if not rule_paths:
            print(f"[WARNING] No YAML rule files (.yml) found in '{rules_directory}'.")
            return []

        for path in rule_paths:
            with open(path, 'r') as f:
                try:
                    # A single file can contain multiple rules separated by ---
                    rules_in_file = yaml.safe_load_all(f)
                    for rule in rules_in_file:
                        if rule and isinstance(rule, dict):
                            self._compile_regex_in_rule(rule)
                            loaded_rules.append(rule)
                except yaml.YAMLError as e:
                    print(f"[ERROR] Error loading rule file {path}: {e}")
        return loaded_rules

    def _compile_regex_in_rule(self, rule_part: Any):
        """Recursively finds and compiles regex patterns in a rule's detection block."""
        if isinstance(rule_part, dict):
            for key, value in rule_part.items():
                if isinstance(value, str) and value.startswith('re:'):
                    try:
                        # Store the compiled regex pattern
                        rule_part[key] = re.compile(value[3:], re.IGNORECASE)
                    except re.error as e:
                        print(f"Invalid regex in rule {rule_part.get('rule_id', 'N/A')}: {value}. Error: {e}")
                        rule_part[key] = None # Invalidate this part of the rule
                else:
                    self._compile_regex_in_rule(value)
        elif isinstance(rule_part, list):
            for i, item in enumerate(rule_part):
                if isinstance(item, str) and item.startswith('re:'):
                    try:
                        rule_part[i] = re.compile(item[3:], re.IGNORECASE)
                    except re.error as e:
                        print(f"Invalid regex in rule: {item}. Error: {e}")
                        rule_part[i] = None
                else:
                    self._compile_regex_in_rule(item)

    def _check_condition(self, selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """
        Checks if an event matches a single selection block in a rule.
        Supports exact matches, list containment, and pre-compiled regex.
        """
        for field, expected_value in selection.items():
            actual_value = event.get(field)
            if actual_value is None:
                return False

            actual_value_str = str(actual_value)

            if isinstance(expected_value, re.Pattern):
                if not expected_value.search(actual_value_str):
                    return False
            elif isinstance(expected_value, list):
                # Check if any of the values in the list match
                match_found = False
                for val in expected_value:
                    if isinstance(val, re.Pattern):
                        if val.search(actual_value_str):
                            match_found = True
                            break
                    elif str(val).lower() in actual_value_str.lower():
                        match_found = True
                        break
                if not match_found:
                    return False
            else: # Simple string match
                if str(expected_value).lower() not in actual_value_str.lower():
                    return False
        return True

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Processes a single normalized log event against all loaded rules.
        
        :param event: A dictionary representing a single log event (CDM).
        :return: A list of "Finding" objects for each rule that matched.
        """
        findings = []
        for rule in self.rules:
            if not rule: continue
            
            detection_logic = rule.get('detection', {})
            condition_str = detection_logic.get('condition', '').lower()
            
            # Simple case: only a 'selection' block is defined
            if 'selection' in detection_logic and not condition_str:
                if self._check_condition(detection_logic['selection'], event):
                    findings.append(self._create_finding(rule, event))
                continue

            # Complex case: a 'condition' string defines the logic
            if condition_str:
                # This is a basic evaluator for "selection and not filter" logic.
                # A production system could use a proper parsing library for more complex boolean logic.
                match = re.match(r'^\s*(\w+)\s+and\s+not\s+(\w+)\s*$', condition_str)
                if match:
                    selection_name, filter_name = match.groups()
                    
                    selection_block = detection_logic.get(selection_name)
                    filter_block = detection_logic.get(filter_name)

                    if (selection_block and filter_block and
                        self._check_condition(selection_block, event) and
                        not self._check_condition(filter_block, event)):
                        
                        findings.append(self._create_finding(rule, event))
                # Simple condition like just "selection"
                elif 'selection' in detection_logic and condition_str == 'selection':
                     if self._check_condition(detection_logic['selection'], event):
                        findings.append(self._create_finding(rule, event))


        return findings

    def _create_finding(self, rule: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Constructs a structured Finding object."""
        return {
            'finding_id': f"FIN-{event.get('id', 'unknown')}",
            'finding_timestamp': event.get('timestamp'),
            'rule': {
                'id': rule.get('rule_id'),
                'name': rule.get('rule_name'),
                'severity': rule.get('severity'),
            },
            'mitre_attack': rule.get('mitre_mapping'),
            'event_details': event,
        }
