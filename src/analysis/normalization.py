# src/analysis/normalization.py
from typing import Dict, Any, List

class CanonicalDataModelMapper:
    """
    A service to normalize raw log events into the CyborEye Canonical Data Model (CDM).
    This ensures that detection rules can be written once and applied to data from any source.
    """

    # This map is the core of the normalization logic.
    # It defines which raw field names map to which canonical field names.
    # The first item in the list is the primary/preferred raw field.
    FIELD_MAP: Dict[str, List[str]] = {
        # Canonical Field       # List of possible raw field names
        'process_commandline':  ['command_line', 'process.command_line', 'cmdline'],
        'process_name':         ['process_name', 'process.name', 'Image'],
        'parent_process_name':  ['parent_process_name', 'parent.process_name', 'ParentImage'],
        'user_name':            ['user', 'user.name', 'account_name', 'UserName'],
        'hostname':             ['hostname', 'host.name', 'Computer'],
        'source_ip':            ['source_ip', 'source.ip', 'src_ip'],
        'destination_ip':       ['destination_ip', 'destination.ip', 'dest_ip'],
        'target_process_name':  ['target_process_name', 'target.process.name', 'TargetImage'],
        'source_process_name':  ['source_process_name', 'source.process.name', 'SourceImage'],
        'service_name':         ['service_name', 'service.name', 'ServiceName'],
        'service_file_name':    ['service_file_name', 'service.file.name', 'ServiceFileName'],
    }

    def normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes a raw event dictionary and returns a new dictionary with canonical field names.
        
        :param event: The raw log event.
        :return: The normalized event, conforming to the CDM.
        """
        normalized_event = event.copy() # Start with the original event
        
        for canonical_name, raw_names in self.FIELD_MAP.items():
            # If the canonical name is already present, we don't need to map it.
            if canonical_name in normalized_event:
                continue

            # Look for the first available raw name in the event
            for raw_name in raw_names:
                if raw_name in event:
                    normalized_event[canonical_name] = event[raw_name]
                    break # Stop after finding the first match
        
        return normalized_event

