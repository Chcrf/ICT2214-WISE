from typing import Any, Dict, Optional
from langgraph.graph import StateGraph, END

from .state import DecompilerState, create_initial_state
from .runtime_settings import update_decompiler_config
from .nodes import (
    parse_wat,
    summarize_symbols,
    lift_functions,
    refine_code,
    finalize_output,
    vulnerability_scanner,
    summarize_output,
)


def create_wat_decompiler_graph():
    """
    Create the LangGraph workflow for WAT -> C decompilation.

    Returns:
        Compiled StateGraph ready for execution
    """

    workflow = StateGraph(DecompilerState)

    workflow.add_node("parse_wat", parse_wat)
    workflow.add_node("summarize_symbols", summarize_symbols)
    workflow.add_node("lift_functions", lift_functions)
    workflow.add_node("refine_code", refine_code)
    workflow.add_node("finalize_output", finalize_output)
    workflow.add_node("vulnerability_scanner", vulnerability_scanner)
    workflow.add_node("summarize_output", summarize_output)

    workflow.set_entry_point("parse_wat")
    workflow.add_edge("parse_wat", "summarize_symbols")
    workflow.add_edge("summarize_symbols", "lift_functions")
    workflow.add_edge("lift_functions", "refine_code")
    workflow.add_edge("refine_code", "finalize_output")
    workflow.add_edge("finalize_output", "vulnerability_scanner")
    workflow.add_edge("vulnerability_scanner", "summarize_output")
    workflow.add_edge("summarize_output", END)

    return workflow.compile()


def decompile_wat(
    input_path,
    output_path=None,
    provider=None,
    model=None,
    wasp_bin=None,
    dynamic_analysis_data=None,
):
    """
    Main entry point: Decompile a WAT or WASM file to C.

    Args:
        input_path: Path to .wat or .wasm file
        output_path: Optional path to save output C file
        provider: LLM provider (anthropic, openrouter, ollama, etc.)
        model: Model name
        wasp_bin: Optional path to WASP binary for graph analysis

    Returns:
        Generated C code as string
    """
    final_code, _ = decompile_wat_with_summary(
        input_path=input_path,
        output_path=output_path,
        provider=provider,
        model=model,
        wasp_bin=wasp_bin,
        dynamic_analysis_data=dynamic_analysis_data,
    )

    return final_code


def decompile_wat_with_summary(
    input_path,
    output_path=None,
    provider=None,
    model=None,
    wasp_bin=None,
    dynamic_analysis_data=None,
):
    """
    Decompile a WAT/WASM file and also return a natural-language summary.

    Returns:
        Tuple of (final_c_code, final_summary)
    """
    final_code, final_summary, _, _ = decompile_wat_with_artifacts(
        input_path=input_path,
        output_path=output_path,
        provider=provider,
        model=model,
        wasp_bin=wasp_bin,
        dynamic_analysis_data=dynamic_analysis_data,
    )
    return final_code, final_summary


def decompile_wat_with_artifacts(
    input_path,
    output_path=None,
    provider=None,
    model=None,
    wasp_bin=None,
    dynamic_analysis_data=None,
):
    """
    Decompile a WAT/WASM file and return code, summary, function name mapping,
    and security findings.

    Returns:
        Tuple of (final_c_code, final_summary, function_name_map, security_report)
    """

    if provider:
        update_decompiler_config(provider=provider)
    if model:
        update_decompiler_config(model=model)

    initial_state = create_initial_state(
        wasm_path=input_path,
        dynamic_analysis=dynamic_analysis_data or {},
    )
    initial_state["wasp_bin"] = wasp_bin

    graph = create_wat_decompiler_graph()

    print("=" * 60)
    print("WISE - WAT to C Decompiler")
    print("=" * 60)
    print()

    final_state = None
    for step in graph.stream(initial_state):
        node_name = list(step.keys())[0]
        final_state = step[node_name]

        if final_state.get("error_message"):
            print(f"  [x] Error in {node_name}: {final_state['error_message']}")
            break
        else:
            print(f"  [ok] Completed: {node_name}")

    print()

    if not final_state:
        raise RuntimeError("Workflow produced no output")

    if final_state.get("error_message"):
        raise RuntimeError(final_state["error_message"])

    final_code = final_state.get("final_c_code", "")
    final_summary = final_state.get("final_summary", "")
    function_name_map = final_state.get("function_name_map", [])

    security_report = final_state.get("security_report", [])
    report_path = final_state.get("security_report_path", "")

    if output_path and final_code:
        with open(output_path, 'w') as f:
            f.write(final_code)
        print(f"Output saved to: {output_path}")

    if security_report:
        print()
        print(f"Security Report: {len(security_report)} vulnerabilities found")
        for i, finding in enumerate(security_report, 1):
            print(f"  {i}. [{finding.get('confidence_score', '?')}] "
                  f"{finding.get('vulnerability_type', 'Unknown')}")
    if report_path:
        print(f"  Full report: {report_path}")

    print("=" * 60)
    print(f"Decompilation complete! Generated {len(final_code)} chars.")
    print("=" * 60)

    return final_code, final_summary, function_name_map, security_report
