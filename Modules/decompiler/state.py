from typing import TypedDict, List, Optional, Dict, Any


class DecompilerState(TypedDict, total=False):

    wasm_path: str
    wat_path: str
    wasm_path_resolved: str
    wasp_bin: Optional[str]

    wat_functions: List[str]
    wat_functions_raw: List[str]
    wat_function_names: List[str]
    wat_function_indices: List[int]
    wat_header: str
    wat_imports: List[str]
    wat_dfgs: List[Optional[str]]
    wat_call_graphs: List[Optional[str]]
    data_dictionary: str
    data_dict_map: Dict[int, str]
    num_functions: int

    symbol_table: Dict[str, str]
    global_symbol_table: Dict[str, str]
    symbol_summaries: Dict[str, str]

    lifted_functions: List[Dict[str, Any]]
    refined_functions: List[Dict[str, Any]]
    final_c_code: str
    final_summary: str
    function_name_map: List[Dict[str, Any]]

    security_report: List[Dict[str, str]]
    security_report_path: str
    dynamic_analysis: Dict[str, Any]

    parse_complete: bool
    lift_complete: bool
    vulnerability_scan_complete: bool
    complete: bool
    error_message: Optional[str]


def create_initial_state(wasm_path="", **kwargs):
    """
    Create an initial state for the WAT->C decompiler workflow.

    Args:
        wasm_path: Path to the WAT or WASM file
        **kwargs: Additional state values

    Returns:
        Initialized DecompilerState
    """
    state: DecompilerState = {
        "wasm_path": wasm_path,
        "wat_path": "",
        "wasm_path_resolved": "",
        "wasp_bin": None,
        "wat_functions": [],
        "wat_functions_raw": [],
        "wat_function_names": [],
        "wat_function_indices": [],
        "wat_header": "",
        "wat_imports": [],
        "wat_dfgs": [],
        "wat_call_graphs": [],
        "data_dictionary": "",
        "data_dict_map": {},
        "num_functions": 0,
        "symbol_table": {},
        "global_symbol_table": {},
        "symbol_summaries": {},
        "lifted_functions": [],
        "refined_functions": [],
        "final_c_code": "",
        "final_summary": "",
        "function_name_map": [],
        "security_report": [],
        "security_report_path": "",
        "dynamic_analysis": {},
        "parse_complete": False,
        "lift_complete": False,
        "vulnerability_scan_complete": False,
        "complete": False,
        "error_message": None,
    }
    state.update(kwargs)
    return state
