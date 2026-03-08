import json
import os
import re
import time
import tempfile
from datetime import datetime
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

try:
    from langchain_community.document_loaders.generic import GenericLoader
    from langchain_community.document_loaders.parsers import LanguageParser
    from langchain_core.documents import Document
    from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
    LANGCHAIN_CODE_CHUNKING_AVAILABLE = True
except ImportError:
    GenericLoader = None
    LanguageParser = None
    Document = None
    Language = None
    RecursiveCharacterTextSplitter = None
    LANGCHAIN_CODE_CHUNKING_AVAILABLE = False

from .state import DecompilerState
from .llm_factory import get_chat_model
from .runtime_settings import get_decompiler_config
from .wat_parser import (
    WatParser,
    wasm_to_wat,
    build_function_structure_hint,
    split_wat_function_inner_blocks,
)
from .prompts import (
    LIFTER_SYSTEM_PROMPT,
    LIFTER_USER_TEMPLATE,
    LIFTER_BATCH_USER_TEMPLATE,
    LIFTER_BLOCK_USER_TEMPLATE,
    LIFTER_STITCH_USER_TEMPLATE,
    GRAPH_CONTEXT_TEMPLATE,
    GRAPH_CONTEXT_NONE,
    SYMBOL_DISCOVERY_SYSTEM_PROMPT,
    SYMBOL_DISCOVERY_USER_TEMPLATE,
    SYMBOL_DISCOVERY_BATCH_USER_TEMPLATE,
    SYMBOL_DISCOVERY_BLOCK_USER_TEMPLATE,
    SYMBOL_DISCOVERY_STITCH_USER_TEMPLATE,
    REFINER_SYSTEM_PROMPT,
    REFINER_BATCH_USER_TEMPLATE,
    REFINER_STITCH_USER_TEMPLATE,
    SUMMARY_SYSTEM_PROMPT,
    SUMMARY_USER_TEMPLATE,
    VULN_SCANNER_SYSTEM_PROMPT,
    VULN_SCANNER_USER_TEMPLATE,
    VULN_VERIFIER_SYSTEM_PROMPT,
    VULN_VERIFIER_USER_TEMPLATE,
)
from .static import (
    parse_vulnerability_json_array,
    parse_verification_response,
    normalize_findings,
    deduplicate_findings,
    validate_evidence,
    write_security_report,
)


def parse_wat(state):
    """
    Parse WAT file into structured function chunks.

    Input: wasm_path (either .wasm or .wat file)
    Output: wat_module with parsed functions and data sections
    """
    input_path = state.get("wasm_path", "")
    wasp_bin = state.get("wasp_bin")

    if not input_path:
        return {
            **state,
            "error_message": "No input file specified",
        }

    if not os.path.exists(input_path):
        return {
            **state,
            "error_message": f"File not found: {input_path}",
        }

    print(f"[Node 1] Parsing: {input_path}")

    try:

        wasm_path = None
        if input_path.endswith('.wasm'):
            wasm_path = input_path
            wat_path = wasm_to_wat(input_path)
            print(f"[Node 1] Converted to WAT: {wat_path}")
        else:
            wat_path = input_path

            potential_wasm = os.path.splitext(input_path)[0] + ".wasm"
            if os.path.exists(potential_wasm):
                wasm_path = potential_wasm

        parser = WatParser(wasp_bin=wasp_bin)
        module = parser.parse_file(wat_path, wasm_path)

        print(f"[Node 1] Found {len(module.functions)} functions")
        print(f"[Node 1] Found {len(module.data_sections)} data sections")

        data_dict = module.get_data_dictionary()
        if data_dict:
            data_dict_str = "\n".join(
                f"  [{offset}]: {repr(content)}"
                for offset, content in sorted(data_dict.items())
            )
            print(f"[Node 1] Data dictionary:")
            for offset, content in sorted(data_dict.items()):
                preview = repr(content)[:50]
                print(f"  [{offset}]: {preview}")
        else:
            data_dict_str = "(no data sections found)"

        return {
            **state,
            "wat_path": wat_path,
            "wasm_path_resolved": wasm_path,
            "wat_functions": [f.to_chunk() for f in module.functions],
            "wat_functions_raw": [f.raw for f in module.functions],
            "wat_function_names": [f.name or f"func_{f.index}" for f in module.functions],
            "wat_function_indices": [f.index for f in module.functions],
            "wat_header": module.raw_header,
            "wat_imports": list(module.imports),
            "wat_dfgs": [f.dfg for f in module.functions],
            "wat_call_graphs": [f.call_graph for f in module.functions],
            "data_dictionary": data_dict_str,
            "data_dict_map": data_dict,
            "num_functions": len(module.functions),
            "symbol_table": {},
            "global_symbol_table": {},
            "symbol_summaries": {},
            "lifted_functions": [],
            "refined_functions": [],
            "parse_complete": True,
        }

    except Exception as e:
        return {
            **state,
            "error_message": f"Failed to parse WAT: {str(e)}",
        }


def summarize_symbols(state):
    """
    Infer global symbol hints from all WAT functions.

    Input: wat_functions_raw, wat_function_names
    Output: symbol_table/global_symbol_table mapping original -> guessed
    """
    if not state.get("parse_complete"):
        return {
            **state,
            "error_message": "WAT parsing not complete",
        }

    wat_functions_raw = state.get("wat_functions_raw", [])
    function_names = state.get("wat_function_names", [])
    module_context = (state.get("wat_header") or "").strip() or "(none)"

    if not wat_functions_raw:
        return {
            **state,
            "error_message": "No functions available for symbol discovery",
        }

    print(
        f"[Node 2] Discovering symbols for {len(wat_functions_raw)} functions")

    config = get_decompiler_config()
    llm = get_chat_model(temperature=0.0)
    batch_prompt = ChatPromptTemplate.from_messages([
        ("system", SYMBOL_DISCOVERY_SYSTEM_PROMPT),
        ("human", SYMBOL_DISCOVERY_BATCH_USER_TEMPLATE),
    ])
    batch_chain = batch_prompt | llm | StrOutputParser()

    single_prompt = ChatPromptTemplate.from_messages([
        ("system", SYMBOL_DISCOVERY_SYSTEM_PROMPT),
        ("human", SYMBOL_DISCOVERY_USER_TEMPLATE),
    ])
    single_chain = single_prompt | llm | StrOutputParser()

    block_prompt = ChatPromptTemplate.from_messages([
        ("system", SYMBOL_DISCOVERY_SYSTEM_PROMPT),
        ("human", SYMBOL_DISCOVERY_BLOCK_USER_TEMPLATE),
    ])
    block_chain = block_prompt | llm | StrOutputParser()

    stitch_prompt = ChatPromptTemplate.from_messages([
        ("system", SYMBOL_DISCOVERY_SYSTEM_PROMPT),
        ("human", SYMBOL_DISCOVERY_STITCH_USER_TEMPLATE),
    ])
    stitch_chain = stitch_prompt | llm | StrOutputParser()

    symbol_table: Dict[str, str] = {}
    symbol_summaries: Dict[str, str] = {}

    batch_size = max(1, int(config.get("symbol_batch_size", 12)))
    max_retries = max(1, int(config.get("llm_max_retries", 3)))

    indexed = list(enumerate(zip(wat_functions_raw, function_names), start=1))
    for batch in _chunk_list(indexed, batch_size):
        payload_lines = []
        expected_names = []
        for global_idx, (func_raw, func_name) in batch:
            expected_names.append(func_name)
            payload_lines.append(
                "\n".join([
                    f"### FUNCTION: {func_name}",
                    f"INDEX: {global_idx}",
                    "WAT:",
                    func_raw,
                ])
            )
        functions_payload = "\n\n".join(payload_lines)

        try:
            response = _invoke_with_retries(
                batch_chain,
                {
                    "functions_payload": functions_payload,
                    "module_context": module_context,
                },
                max_retries=max_retries,
                node_label="Node 2 batch symbol discovery",
            )
            parsed = _parse_symbol_batch_response(response)
        except Exception as e:
            print(
                f"[Node 2]   Batch failed, falling back to single calls: {e}")
            parsed = {}

        for _, (func_raw, func_name) in batch:
            if func_name in parsed:
                guessed_name, summary = parsed[func_name]
            else:
                print(
                    f"[Node 2]   Missing batch output for {func_name}, using single fallback")
                guessed_name, summary = _discover_symbol_single_then_blocks(
                    function_name=func_name,
                    func_raw=func_raw,
                    module_context=module_context,
                    single_chain=single_chain,
                    block_chain=block_chain,
                    stitch_chain=stitch_chain,
                    max_retries=max_retries,
                    max_prompt_tokens=max(
                        256, int(config.get("max_prompt_tokens", 12000))),
                )

            symbol_table[func_name] = guessed_name
            symbol_summaries[func_name] = summary
            print(f"[Node 2]   {func_name} -> {guessed_name} ({summary})")

    return {
        **state,
        "symbol_table": symbol_table,
        "global_symbol_table": symbol_table,
        "symbol_summaries": symbol_summaries,
    }


def _parse_symbol_discovery_line(line, fallback_name):
    """Parse `<canonical_name>|<summary>` returned by symbol discovery pass."""
    cleaned = " ".join((line or "").strip().split())
    if "|" in cleaned:
        left, right = cleaned.split("|", 1)
        guessed = left.strip()
        summary = right.strip() or "no summary"
    else:
        guessed = cleaned.strip()
        summary = "no summary"

    if not guessed:
        guessed = fallback_name

    guessed = _to_c_identifier(guessed)
    if not guessed:
        guessed = _to_c_identifier(
            f"{fallback_name}_decompiled") or "decompiled_function"

    return guessed, summary


def _to_c_identifier(name):
    """Normalize text to a valid C identifier in snake_case-like form."""
    name = name.lower().strip()
    name = re.sub(r"[^a-z0-9_]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        return ""
    if not re.match(r"[a-zA-Z_]", name):
        name = f"f_{name}"
    return name


def _truncate_for_fallback(text, max_chars, label):
    """Lightweight truncation used only in inner-block fallback prompts."""
    value = (text or "").strip()
    if len(value) <= max_chars:
        return value
    return value[:max_chars].rstrip() + f"\n... [{label} truncated for fallback] ..."


def _discover_symbol_single_then_blocks(
    function_name,
    func_raw,
    module_context,
    single_chain,
    block_chain,
    stitch_chain,
    max_retries,
    max_prompt_tokens,
):
    """
    Symbol discovery fallback:
    single-function call -> inner-block calls -> stitch.
    """
    try:
        line = _invoke_with_retries(
            single_chain,
            {
                "function_name": function_name,
                "wat_code": func_raw,
                "module_context": module_context,
            },
            max_retries=max_retries,
            node_label=f"Node 2 single symbol discovery ({function_name})",
        ).strip()
        return _parse_symbol_discovery_line(line, fallback_name=function_name)
    except Exception as e:
        print(f"[Node 2]   Single fallback failed for {function_name}: {e}")

    function_structure = build_function_structure_hint(func_raw)
    blocks = split_wat_function_inner_blocks(
        func_raw, max_prompt_tokens=max_prompt_tokens)
    if not blocks:
        guessed = _to_c_identifier(
            f"{function_name}_decompiled") or "decompiled_function"
        return guessed, "heuristic fallback name"

    print(
        f"[Node 2]   Falling back to inner-block discovery for {function_name} ({len(blocks)} blocks)")
    block_outputs: List[str] = []
    for i, block in enumerate(blocks, start=1):
        try:
            line = _invoke_with_retries(
                block_chain,
                {
                    "function_name": function_name,
                    "block_index": i,
                    "total_blocks": len(blocks),
                    "function_structure": function_structure,
                    "wat_block": block,
                },
                max_retries=max_retries,
                node_label=f"Node 2 block symbol discovery ({function_name}) #{i}",
            ).strip()
            if line:
                block_outputs.append(f"{i}. {line}")
        except Exception as e:
            print(f"[Node 2]   Block {i} failed for {function_name}: {e}")

    if not block_outputs:
        guessed = _to_c_identifier(
            f"{function_name}_decompiled") or "decompiled_function"
        return guessed, "heuristic fallback name"

    try:
        stitch_module_context = _truncate_for_fallback(
            module_context, 20000, "module context")
        stitched = _invoke_with_retries(
            stitch_chain,
            {
                "module_context": stitch_module_context,
                "function_name": function_name,
                "function_structure": function_structure,
                "block_analyses": "\n".join(block_outputs),
            },
            max_retries=max_retries,
            node_label=f"Node 2 stitch symbol discovery ({function_name})",
        ).strip()
        return _parse_symbol_discovery_line(stitched, fallback_name=function_name)
    except Exception as e:
        print(f"[Node 2]   Stitch failed for {function_name}: {e}")
        guessed = _to_c_identifier(
            f"{function_name}_decompiled") or "decompiled_function"
        return guessed, "heuristic fallback name"


def _lift_single_then_blocks(
    func,
    single_chain,
    block_chain,
    stitch_chain,
    symbol_table,
    data_dictionary,
    imports_section,
    max_retries,
    max_prompt_tokens,
):
    """
    Lift fallback pipeline:
    single-function call -> inner-block calls -> stitch full function.
    """
    original_name = str(func.get("original_name", "unknown"))
    suggested_name = str(func.get("name", original_name))
    func_raw = str(func.get("func_raw", ""))
    graph_context = str(func.get("graph_context", GRAPH_CONTEXT_NONE))
    function_info = "\n".join([
        f"WASM Index: {func.get('index', 'unknown')}",
        f"Original Name: {original_name}",
        f"Suggested Name: {suggested_name}",
    ])

    try:
        single_result = _invoke_with_retries(
            single_chain,
            {
                "function_info": function_info,
                "wat_code": func_raw,
                "graph_context": graph_context,
                "symbol_table": symbol_table,
                "data_dictionary": data_dictionary,
                "imports_section": imports_section,
            },
            max_retries=max_retries,
            node_label=f"Node 3 single lift ({original_name})",
        )
        return _clean_llm_output(single_result)
    except Exception as e:
        print(f"[Node 3]   Single fallback failed for {original_name}: {e}")

    blocks = split_wat_function_inner_blocks(
        func_raw, max_prompt_tokens=max_prompt_tokens)
    if not blocks:
        return ""

    function_structure = build_function_structure_hint(func_raw)
    symbol_table_fallback = _truncate_for_fallback(
        symbol_table, 18000, "symbol table")
    data_dictionary_fallback = _truncate_for_fallback(
        data_dictionary, 32000, "data dictionary")
    imports_fallback = _truncate_for_fallback(
        imports_section, 12000, "imports")
    print(
        f"[Node 3]   Falling back to inner-block lifting for {original_name} ({len(blocks)} blocks)")

    block_results: List[tuple[int, str, str]] = []
    for i, block in enumerate(blocks, start=1):
        try:
            fragment = _invoke_with_retries(
                block_chain,
                {
                    "function_name": original_name,
                    "suggested_name": suggested_name,
                    "function_structure": function_structure,
                    "block_index": i,
                    "total_blocks": len(blocks),
                    "wat_block": block,
                    "symbol_table": symbol_table_fallback,
                    "data_dictionary": data_dictionary_fallback,
                    "imports_section": imports_fallback,
                },
                max_retries=max_retries,
                node_label=f"Node 3 block lift ({original_name}) #{i}",
            ).strip()
            if fragment:
                block_results.append((i, block, _clean_llm_output(fragment)))
        except Exception as e:
            print(f"[Node 3]   Block {i} failed for {original_name}: {e}")

    if not block_results:
        return ""

    payload_parts = []
    for idx, wat_block, c_fragment in block_results:
        payload_parts.append(
            "\n".join([
                f"=== BLOCK {idx} ===",
                "[WAT]",
                wat_block,
                "[C_FRAGMENT]",
                c_fragment,
            ])
        )
    block_payload = "\n\n".join(payload_parts)

    try:
        stitched = _invoke_with_retries(
            stitch_chain,
            {
                "function_name": original_name,
                "suggested_name": suggested_name,
                "function_structure": function_structure,
                "symbol_table": symbol_table_fallback,
                "data_dictionary": data_dictionary_fallback,
                "imports_section": imports_fallback,
                "block_payload": block_payload,
            },
            max_retries=max_retries,
            node_label=f"Node 3 stitch lift ({original_name})",
        )
        return _clean_llm_output(stitched)
    except Exception as e:
        print(f"[Node 3]   Stitch failed for {original_name}: {e}")
        return ""


def lift_functions(state):
    """
    Convert each WAT function to C using LLM.

    Input: wat_functions, data_dictionary
    Output: lifted_functions (C code for each function)
    """
    if not state.get("parse_complete"):
        return {
            **state,
            "error_message": "WAT parsing not complete",
        }

    wat_functions = state.get("wat_functions", [])
    wat_functions_raw = state.get("wat_functions_raw", [])
    function_names = state.get("wat_function_names", [])
    function_indices = state.get("wat_function_indices", [])
    wat_dfgs = state.get("wat_dfgs", [])
    wat_call_graphs = state.get("wat_call_graphs", [])
    data_dictionary = state.get("data_dictionary", "")
    wat_imports = state.get("wat_imports", [])
    symbol_table = state.get(
        "global_symbol_table") or state.get("symbol_table") or {}

    if not wat_functions:
        return {
            **state,
            "error_message": "No functions to lift",
        }

    config = get_decompiler_config()
    print(f"[Node 3] Lifting {len(wat_functions)} functions to C")

    llm = get_chat_model()

    batch_prompt = ChatPromptTemplate.from_messages([
        ("system", LIFTER_SYSTEM_PROMPT),
        ("human", LIFTER_BATCH_USER_TEMPLATE),
    ])
    batch_chain = batch_prompt | llm | StrOutputParser()

    single_prompt = ChatPromptTemplate.from_messages([
        ("system", LIFTER_SYSTEM_PROMPT),
        ("human", LIFTER_USER_TEMPLATE),
    ])
    single_chain = single_prompt | llm | StrOutputParser()

    block_prompt = ChatPromptTemplate.from_messages([
        ("system", LIFTER_SYSTEM_PROMPT),
        ("human", LIFTER_BLOCK_USER_TEMPLATE),
    ])
    block_chain = block_prompt | llm | StrOutputParser()

    stitch_prompt = ChatPromptTemplate.from_messages([
        ("system", LIFTER_SYSTEM_PROMPT),
        ("human", LIFTER_STITCH_USER_TEMPLATE),
    ])
    stitch_chain = stitch_prompt | llm | StrOutputParser()

    lifted_functions: List[Dict[str, Any]] = []
    by_name: Dict[str, Dict[str, Any]] = {}

    max_retries = max(1, int(config.get("llm_max_retries", 3)))
    max_prompt_tokens = max(256, int(config.get("max_prompt_tokens", 12000)))
    trust_batch_order = bool(config.get("trust_batch_order_mapping", True))
    symbol_table_str = _format_symbol_table(symbol_table)
    imports_section = "\n".join(wat_imports) if wat_imports else "(none)"

    function_records = []
    for i, (func_raw, func_name) in enumerate(zip(wat_functions_raw, function_names)):
        wasm_index = function_indices[i] if i < len(function_indices) else i
        guessed_name = symbol_table.get(func_name, "")
        dfg = wat_dfgs[i] if i < len(wat_dfgs) else None
        call_graph = wat_call_graphs[i] if i < len(wat_call_graphs) else None
        if dfg or call_graph:
            graph_context = GRAPH_CONTEXT_TEMPLATE.format(
                dfg=dfg or "(not available)",
                call_graph=call_graph or "(not available)",
            )
        else:
            graph_context = GRAPH_CONTEXT_NONE
        function_records.append({
            "index": wasm_index,
            "original_name": func_name,
            "name": guessed_name or func_name,
            "func_raw": func_raw,
            "graph_context": graph_context,
        })

    estimated_lift_tokens = _estimate_lift_prompt_tokens(
        function_records=function_records,
        symbol_table=symbol_table_str,
        data_dictionary=data_dictionary,
        imports_section=imports_section,
    )
    batches = _build_adaptive_batches(
        items=function_records,
        max_prompt_tokens=max_prompt_tokens,
        estimate_fn=lambda subset: _estimate_lift_prompt_tokens(
            function_records=subset,
            symbol_table=symbol_table_str,
            data_dictionary=data_dictionary,
            imports_section=imports_section,
        ),
        node_label="Node 3",
    )
    if len(batches) == 1 and len(batches[0]) == len(function_records):
        print(
            f"[Node 3] Estimated prompt tokens {estimated_lift_tokens} within limit {max_prompt_tokens}; using all-functions batch mode"
        )
    elif all(len(b) == 1 for b in batches):
        print(
            f"[Node 3] Estimated prompt tokens {estimated_lift_tokens} exceed limit {max_prompt_tokens}; using function-by-function mode"
        )
    else:
        sizes = ", ".join(str(len(b)) for b in batches)
        print(
            f"[Node 3] Estimated prompt tokens {estimated_lift_tokens} exceed limit {max_prompt_tokens}; using adaptive batches [{sizes}]"
        )

    for batch in batches:
        batch_names = [f["original_name"] for f in batch]
        print(f"[Node 3] Lifting batch: {', '.join(batch_names)}")

        payload_parts = []
        for func in batch:
            payload_parts.append(
                "\n".join([
                    f"=== FUNCTION:{func['original_name']} ===",
                    f"INDEX: {func['index']}",
                    f"SUGGESTED_NAME: {func['name']}",
                    "GRAPH_CONTEXT:",
                    func["graph_context"],
                    "WAT_CODE:",
                    func["func_raw"],
                ])
            )
        functions_payload = "\n\n".join(payload_parts)

        try:
            print(f"[Node 3]   Payload size: {len(functions_payload)} chars")
            batch_response = _invoke_with_retries(
                batch_chain,
                {
                    "functions_payload": functions_payload,
                    "symbol_table": symbol_table_str,
                    "data_dictionary": data_dictionary,
                    "imports_section": imports_section,
                },
                max_retries=max_retries,
                node_label="Node 3 batch lifting",
                validator=_batch_has_any_markers,
            )
            parsed_batch = _extract_batch_functions(
                batch_response,
                batch_names,
                allow_order_fallback=trust_batch_order,
            )
        except Exception as e:
            print(f"[Node 3]   Batch lift failed: {e}")
            parsed_batch = {}

        for func in batch:
            original_name = func["original_name"]
            c_code = parsed_batch.get(original_name, "").strip()

            if not c_code:
                print(
                    f"[Node 3]   Missing batch output for {original_name}, using single fallback")
                c_code = _lift_single_then_blocks(
                    func=func,
                    single_chain=single_chain,
                    block_chain=block_chain,
                    stitch_chain=stitch_chain,
                    symbol_table=symbol_table_str,
                    data_dictionary=data_dictionary,
                    imports_section=imports_section,
                    max_retries=max_retries,
                    max_prompt_tokens=max_prompt_tokens,
                )
                if not c_code:
                    c_code = f"/* ERROR: Missing batch output for {original_name} */"

            c_code = _clean_llm_output(c_code)
            result = {
                "name": func["name"],
                "original_name": original_name,
                "index": func["index"],
                "c_code": c_code,
            }
            by_name[original_name] = result
            print(
                f"[Node 3]   Generated {len(c_code)} chars for {original_name}")

    for record in function_records:
        lifted_functions.append(by_name.get(record["original_name"], {
            "name": record["name"],
            "original_name": record["original_name"],
            "index": record["index"],
            "c_code": f"/* ERROR: Missing lifted output for {record['original_name']} */",
        }))

    return {
        **state,
        "lifted_functions": lifted_functions,
        "lift_complete": True,
    }


def _format_symbol_table(symbol_table):
    """Format symbol table for prompt injection."""
    if not symbol_table:
        return "(none)"
    return "\n".join(
        f"- {src} -> {dst}" for src, dst in sorted(symbol_table.items())
    )


def _chunk_list(items, chunk_size):
    """Split a list into fixed-size chunks."""
    if chunk_size <= 0:
        chunk_size = 1
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def _estimate_tokens(text):
    """Rough token estimate using character count (conservative heuristic)."""
    if not text:
        return 0

    return int(len(text) / 3.6) + 8


def _estimate_lift_prompt_tokens(
    function_records,
    symbol_table,
    data_dictionary,
    imports_section,
):
    """Estimate input token footprint for lift batch payload."""
    total = 120
    total += _estimate_tokens(symbol_table)
    total += _estimate_tokens(data_dictionary)
    total += _estimate_tokens(imports_section)
    for func in function_records:
        total += _estimate_tokens(func.get("original_name", ""))
        total += _estimate_tokens(func.get("name", ""))
        total += _estimate_tokens(func.get("graph_context", ""))
        total += _estimate_tokens(func.get("func_raw", ""))
        total += 40
    return total


def _estimate_refine_prompt_tokens(functions):
    """Estimate input token footprint for refine batch payload."""
    total = 100
    for func in functions:
        total += _estimate_tokens(str(func.get("original_name")
                                  or func.get("name") or ""))
        total += _estimate_tokens(func.get("c_code", ""))
        total += 28
    return total


def _split_text_by_token_budget(text, chunk_tokens, overlap_tokens=0):
    """Fallback splitter when LangChain source-code chunking is unavailable."""
    if not text:
        return []

    lines = text.splitlines()
    chunks: List[str] = []
    cur: List[str] = []
    cur_tokens = 0
    for line in lines:
        line_tokens = _estimate_tokens(line) + 1
        if cur and (cur_tokens + line_tokens) > chunk_tokens:
            chunks.append("\n".join(cur).strip())
            if overlap_tokens > 0:
                carry: List[str] = []
                carry_tokens = 0
                for prev in reversed(cur):
                    t = _estimate_tokens(prev) + 1
                    if carry and (carry_tokens + t) > overlap_tokens:
                        break
                    carry.insert(0, prev)
                    carry_tokens += t
                cur = carry
                cur_tokens = carry_tokens
            else:
                cur = []
                cur_tokens = 0
        cur.append(line)
        cur_tokens += line_tokens
    if cur:
        chunks.append("\n".join(cur).strip())

    return [c for c in chunks if c]


def _split_c_code_for_llm(
    c_code,
    max_prompt_tokens,
    node_label,
    chunk_size_cap_chars=24000,
):
    """
    Chunk C code using LangChain source-code tooling when available.

    Approach aligned with LangChain source-code docs:
    - Parse source units with `GenericLoader + LanguageParser(Language.C)`.
    - Split with `RecursiveCharacterTextSplitter.from_language(Language.C, ...)`.
    """
    text = (c_code or "").strip()
    if not text:
        return []

    token_threshold = max(192, int(max_prompt_tokens * 0.7))
    if _estimate_tokens(text) <= token_threshold:
        return [text]

    chunk_size = max(1800, min(chunk_size_cap_chars,
                     int(max_prompt_tokens * 2.8)))
    chunk_overlap = max(120, min(700, int(chunk_size * 0.1)))

    try:
        if not LANGCHAIN_CODE_CHUNKING_AVAILABLE:
            raise RuntimeError("LangChain source-code loaders are unavailable")
        with tempfile.TemporaryDirectory(prefix="wise_c_chunk_") as tmpdir:
            src_path = os.path.join(tmpdir, "unit.c")
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(text)

            loader = GenericLoader.from_filesystem(
                tmpdir,
                glob="*.c",
                suffixes=[".c"],
                parser=LanguageParser(language=Language.C, parser_threshold=0),
            )
            docs = loader.load()

        if not docs:
            docs = [Document(page_content=text, metadata={
                             "source": "inline.c"})]

        splitter = RecursiveCharacterTextSplitter.from_language(
            language=Language.C,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )
        split_docs = splitter.split_documents(docs)
        chunks = [d.page_content.strip()
                  for d in split_docs if getattr(d, "page_content", "").strip()]
        if chunks:
            return chunks
    except Exception as e:
        print(
            f"[{node_label}] LangChain C chunking unavailable, using token fallback: {e}")

    return _split_text_by_token_budget(
        text=text,
        chunk_tokens=max(160, int(chunk_size / 3)),
        overlap_tokens=max(0, int(chunk_overlap / 3)),
    )


def _build_adaptive_batches(
    items,
    max_prompt_tokens,
    estimate_fn,
    node_label,
):
    """
    Build adaptive contiguous batches that fit token budget.

    Strategy:
    - Try largest possible prefix of remaining items.
    - If too large, shrink via binary search.
    - Continue until all items are assigned.
    - Falls back to one item when necessary.
    """
    remaining = list(items)
    batches: List[List[Any]] = []

    while remaining:

        if estimate_fn(remaining) <= max_prompt_tokens:
            batches.append(remaining)
            break

        lo, hi = 1, len(remaining)
        best = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            est = estimate_fn(remaining[:mid])
            if est <= max_prompt_tokens:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1

        if best == 0:
            one_est = estimate_fn(remaining[:1])
            print(
                f"[{node_label}] Single item estimate {one_est} exceeds limit {max_prompt_tokens}; forcing 1-item batch"
            )
            best = 1

        batches.append(remaining[:best])
        remaining = remaining[best:]

    return batches


def _invoke_with_retries(
    chain,
    payload,
    max_retries,
    node_label,
    validator=None,
):
    """Invoke an LLM chain with bounded retries and optional output validation."""
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            print(
                f"[{node_label}] invoking LLM (attempt {attempt}/{max_retries})...")
            response = chain.invoke(payload)
            if not isinstance(response, str):
                response = str(response)
            cleaned = response.strip()
            if validator and not validator(cleaned):
                raise ValueError("Output validation failed")
            return cleaned
        except Exception as e:
            last_error = e
            print(f"[{node_label}] attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(min(0.8 * attempt, 2.0))
            print(f"[{node_label}] retrying...")
    raise RuntimeError(
        f"{node_label} failed after {max_retries} attempts: {last_error}")


def _parse_symbol_batch_response(response):
    """Parse lines formatted as `<original>|<canonical>|<summary>`."""
    result: Dict[str, Tuple[str, str]] = {}
    for raw_line in response.splitlines():
        line = raw_line.strip()
        if not line or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|", 2)]
        if len(parts) != 3:
            continue
        original_name, guessed_raw, summary = parts
        if not original_name:
            continue
        guessed = _to_c_identifier(guessed_raw) or _to_c_identifier(
            f"{original_name}_decompiled") or "decompiled_function"
        result[original_name] = (guessed, summary or "no summary")
    return result


def _extract_framed_functions(response):
    """Extract framed blocks between FUNCTION_START/FUNCTION_END markers."""
    pattern = re.compile(
        r"===\s*FUNCTION_START:(?P<name>[^=\n]+?)\s*===\s*(?P<body>.*?)\s*===\s*FUNCTION_END:(?P=name)\s*===",
        re.DOTALL,
    )
    result: Dict[str, str] = {}
    for match in pattern.finditer(response):
        name = match.group("name").strip()
        body = match.group("body").strip()
        if name and body:
            result[name] = body
    return result


def _extract_batch_functions(
    response,
    expected_names,
    allow_order_fallback=False,
):
    """
    Robustly extract batch outputs and map them back to expected function names.

    Supports:
    1) Strict FUNCTION_START/FUNCTION_END framing
    2) Loose `=== FUNCTION:<name> ===` section framing
    3) Index-like labels (`1`, `0`, `func_1`) mapped by index/name normalization

    Optional:
    - order fallback mapping for unmatched blocks when `allow_order_fallback=True`.
    """
    expected = [n.strip() for n in expected_names if n and n.strip()]
    if not expected:
        return {}

    mapped: Dict[str, str] = {}

    strict = _extract_framed_functions(response)
    mapped.update(_map_blocks_to_expected(strict, expected))
    if len(mapped) >= len(expected):
        return mapped

    loose_pattern = re.compile(
        r"===\s*FUNCTION\s*:\s*(?P<name>[^=\n]+?)\s*===\s*(?P<body>.*?)(?=(?:===\s*FUNCTION\s*:)|\Z)",
        re.DOTALL,
    )
    loose_blocks: Dict[str, str] = {}
    for m in loose_pattern.finditer(response):
        name = m.group("name").strip()
        body = m.group("body").strip()
        if name and body:
            loose_blocks[name] = body

    mapped.update(_map_blocks_to_expected(
        loose_blocks, expected, keep_existing=mapped))
    if len(mapped) >= len(expected):
        return mapped

    if not allow_order_fallback:
        return mapped

    ordered_bodies: List[str] = []
    ordered_bodies.extend([v for _, v in strict.items() if v])
    ordered_bodies.extend([v for _, v in loose_blocks.items() if v])

    seen = set()
    unique_bodies: List[str] = []
    for body in ordered_bodies:
        key = body.strip()
        if key and key not in seen:
            seen.add(key)
            unique_bodies.append(key)

    if unique_bodies:
        missing = [n for n in expected if n not in mapped]
        for name, body in zip(missing, unique_bodies):
            if body and not mapped.get(name):
                mapped[name] = body

    return mapped


def _normalize_label(label):
    """Normalize label text for tolerant key matching."""
    label = (label or "").strip().lower()
    label = re.sub(r"[^a-z0-9]+", "", label)
    return label


def _label_to_index(label, total):
    """Convert common numeric labels into a 0-based index."""
    raw = (label or "").strip().lower()
    if not raw:
        return None

    m = re.search(r"(\d+)$", raw)
    if not m:
        return None

    value = int(m.group(1))

    if 0 <= value < total:
        return value
    if 1 <= value <= total:
        return value - 1
    return None


def _map_blocks_to_expected(
    blocks,
    expected,
    keep_existing=None,
):
    """Map parsed blocks to expected function names using tolerant matching."""
    mapped = dict(keep_existing or {})
    expected_set = set(expected)
    norm_to_expected = {_normalize_label(n): n for n in expected}

    for raw_name, body in blocks.items():
        if not body:
            continue
        if raw_name in expected_set and raw_name not in mapped:
            mapped[raw_name] = body
            continue

        norm = _normalize_label(raw_name)
        target = norm_to_expected.get(norm)
        if target and target not in mapped:
            mapped[target] = body
            continue

        idx = _label_to_index(raw_name, len(expected))
        if idx is not None:
            target = expected[idx]
            if target not in mapped:
                mapped[target] = body

    return mapped


def _batch_has_any_markers(response):
    """Light validator: ensure the response looks like a multi-function batch payload."""
    text = response or ""
    if "FUNCTION_START:" in text and "FUNCTION_END:" in text:
        return True
    return bool(re.search(r"===\s*FUNCTION\s*:", text))


def refine_code(state):
    """
    Refine raw C output into cleaner, idiomatic C while preserving semantics.

    Input: lifted_functions
    Output: refined_functions
    """
    if not state.get("lift_complete"):
        return {
            **state,
            "error_message": "Function lifting not complete",
        }

    lifted_functions = state.get("lifted_functions", [])
    if not lifted_functions:
        return {
            **state,
            "error_message": "No lifted functions to refine",
        }

    config = get_decompiler_config()
    print(f"[Node 4] Refining {len(lifted_functions)} lifted functions")

    llm = get_chat_model(temperature=0.0)
    batch_prompt = ChatPromptTemplate.from_messages([
        ("system", REFINER_SYSTEM_PROMPT),
        ("human", REFINER_BATCH_USER_TEMPLATE),
    ])
    batch_chain = batch_prompt | llm | StrOutputParser()
    stitch_prompt = ChatPromptTemplate.from_messages([
        ("system", REFINER_SYSTEM_PROMPT),
        ("human", REFINER_STITCH_USER_TEMPLATE),
    ])
    stitch_chain = stitch_prompt | llm | StrOutputParser()

    max_retries = max(1, int(config.get("llm_max_retries", 3)))
    max_prompt_tokens = max(256, int(config.get("max_prompt_tokens", 12000)))
    trust_batch_order = bool(config.get("trust_batch_order_mapping", True))

    segmented_records: List[Dict[str, Any]] = []
    function_segments: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for i, func in enumerate(lifted_functions):
        original_name = str(func.get("original_name")
                            or func.get("name") or f"func_{i}")
        code = str(func.get("c_code", "") or "")
        chunks = _split_c_code_for_llm(
            c_code=code,
            max_prompt_tokens=max_prompt_tokens,
            node_label="Node 4",
            chunk_size_cap_chars=22000,
        )
        if not chunks:
            chunks = [code]

        if len(chunks) > 1:
            print(
                f"[Node 4] Chunked {original_name} into {len(chunks)} C segments")

        for seg_idx, chunk in enumerate(chunks, start=1):
            seg_name = f"{original_name}::segment_{seg_idx}_of_{len(chunks)}"
            rec = {
                **func,
                "original_name": original_name,
                "segment_name": seg_name,
                "segment_index": seg_idx,
                "segment_total": len(chunks),
                "c_code": chunk,
            }
            segmented_records.append(rec)
            function_segments[original_name].append(rec)

    estimated_refine_tokens = _estimate_refine_prompt_tokens(segmented_records)
    batches = _build_adaptive_batches(
        items=segmented_records,
        max_prompt_tokens=max_prompt_tokens,
        estimate_fn=_estimate_refine_prompt_tokens,
        node_label="Node 4",
    )
    if len(batches) == 1 and len(batches[0]) == len(segmented_records):
        print(
            f"[Node 4] Estimated prompt tokens {estimated_refine_tokens} within limit {max_prompt_tokens}; using all-functions batch mode"
        )
    elif all(len(b) == 1 for b in batches):
        print(
            f"[Node 4] Estimated prompt tokens {estimated_refine_tokens} exceed limit {max_prompt_tokens}; using function-by-function mode"
        )
    else:
        sizes = ", ".join(str(len(b)) for b in batches)
        print(
            f"[Node 4] Estimated prompt tokens {estimated_refine_tokens} exceed limit {max_prompt_tokens}; using adaptive batches [{sizes}]"
        )

    refined_segments: Dict[str, str] = {}
    for batch in batches:
        batch_names = [str(f.get("segment_name") or f.get(
            "original_name") or f.get("name") or "") for f in batch]
        print(f"[Node 4] Refining batch: {', '.join(batch_names)}")

        payload_parts = []
        for func in batch:
            original_name = str(func.get("segment_name") or func.get(
                "original_name") or func.get("name") or "unknown")
            payload_parts.append(
                "\n".join([
                    f"=== FUNCTION:{original_name} ===",
                    "C_CODE:",
                    func.get("c_code", ""),
                ])
            )
        functions_payload = "\n\n".join(payload_parts)

        try:
            response = _invoke_with_retries(
                batch_chain,
                {"functions_payload": functions_payload},
                max_retries=max_retries,
                node_label="Node 4 batch refinement",
                validator=_batch_has_any_markers,
            )
            parsed = _extract_batch_functions(
                response,
                batch_names,
                allow_order_fallback=trust_batch_order,
            )
        except Exception as e:
            print(f"[Node 4]   Batch refine failed: {e}")
            parsed = {}

        for i, func in enumerate(batch):
            segment_name = str(func.get("segment_name") or func.get(
                "original_name") or func.get("name") or f"segment_{i}")
            refined = parsed.get(segment_name, "").strip()
            if not refined:
                refined = func.get("c_code", "")
            refined_segments[segment_name] = _clean_llm_output(refined)

    refined_functions = []
    for func in lifted_functions:
        original_name = str(func.get("original_name")
                            or func.get("name") or "unknown")
        segments = sorted(
            function_segments.get(original_name, []),
            key=lambda rec: int(rec.get("segment_index", 0)),
        )

        if not segments:
            refined_functions.append(func)
            continue

        refined_parts = []
        for seg in segments:
            segment_name = str(seg.get("segment_name") or "")
            refined_parts.append(
                refined_segments.get(segment_name, str(
                    seg.get("c_code", ""))).strip()
            )

        if len(refined_parts) == 1:
            final_code = refined_parts[0]
        else:
            segments_payload = "\n\n".join(
                f"=== SEGMENT {idx + 1} ===\n{part}" for idx, part in enumerate(refined_parts)
            )
            try:
                final_code = _invoke_with_retries(
                    stitch_chain,
                    {
                        "function_name": str(func.get("name") or original_name),
                        "original_name": original_name,
                        "total_segments": len(refined_parts),
                        "segments_payload": segments_payload,
                    },
                    max_retries=max_retries,
                    node_label=f"Node 4 stitch refinement ({original_name})",
                )
            except Exception as e:
                print(f"[Node 4]   Stitch failed for {original_name}: {e}")
                final_code = "\n".join(refined_parts)

        refined_functions.append({
            **func,
            "c_code": _clean_llm_output(final_code),
        })

    return {
        **state,
        "refined_functions": refined_functions,
    }


def _clean_llm_output(code):
    """
    Clean LLM output to produce valid C code.

    Removes:
    - Markdown code blocks (```c ... ```)
    - Leading/trailing whitespace
    """
    code = code.strip()

    if code.startswith("```"):
        lines = code.split("\n")

        lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        code = "\n".join(lines)

    return code.strip()


def finalize_output(state):
    """
    Combine all lifted functions into final compilable C output.

    Input: lifted_functions, wat_header
    Output: final_c_code (must compile with gcc)
    """
    if not state.get("lift_complete"):
        return {
            **state,
            "error_message": "Function lifting not complete",
        }

    lifted_functions = state.get(
        "refined_functions") or state.get("lifted_functions", [])
    data_dict_map = state.get("data_dict_map", {})

    print(f"[Node 5] Finalizing output from {len(lifted_functions)} functions")

    lines = []

    lines.append("/*")
    lines.append(" * Decompiled from WebAssembly")
    lines.append(
        " * Generated by WISE - WebAssembly Intelligent Security Engine")
    lines.append(" */")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("#include <stddef.h>")
    lines.append("#include <string.h>")
    lines.append("#include <stdlib.h>")
    lines.append("")

    lines.append("/* WebAssembly linear memory (64KB = 1 page) */")
    lines.append("uint8_t memory[65536];")
    lines.append("")

    lines.append("/* Memory access helpers */")
    lines.append("#define MEM_I32(addr) (*(int32_t*)(memory + (addr)))")
    lines.append("#define MEM_U32(addr) (*(uint32_t*)(memory + (addr)))")
    lines.append("#define MEM_I16(addr) (*(int16_t*)(memory + (addr)))")
    lines.append("#define MEM_U16(addr) (*(uint16_t*)(memory + (addr)))")
    lines.append("#define MEM_I8(addr) (*(int8_t*)(memory + (addr)))")
    lines.append("#define MEM_U8(addr) (*(uint8_t*)(memory + (addr)))")
    lines.append("")

    if data_dict_map:
        lines.append("/* Initialize data section contents */")
        lines.append("void __wasm_init_memory(void) {")
        for offset, content in sorted(data_dict_map.items()):

            escaped = ""
            for ch in content:
                if ch == '\\':
                    escaped += "\\\\"
                elif ch == '"':
                    escaped += '\\"'
                elif ch == '\n':
                    escaped += "\\n"
                elif ch == '\r':
                    escaped += "\\r"
                elif ch == '\t':
                    escaped += "\\t"
                elif ch == '\0':
                    escaped += "\\0"
                elif ord(ch) < 32 or ord(ch) > 126:
                    escaped += f"\\x{ord(ch):02x}"
                else:
                    escaped += ch
            lines.append(
                f'    memcpy(memory + {offset}, "{escaped}", {len(content)});')
        lines.append("}")
        lines.append("")

    if len(lifted_functions) > 1:
        lines.append("/* Forward declarations */")
        for func in lifted_functions:

            c_code = func.get("c_code", "")

            for line in c_code.split('\n'):
                line = line.strip()
                if line and not line.startswith('//') and not line.startswith('/*'):
                    if '(' in line and ')' in line:

                        sig = line.rstrip('{').strip()
                        if not sig.endswith(';'):
                            sig += ';'
                        lines.append(sig)
                        break
        lines.append("")

    for func in lifted_functions:
        lines.append(func["c_code"])
        lines.append("")

    lines.append("/* Main function for standalone compilation test */")
    lines.append("#ifdef STANDALONE_TEST")
    lines.append("int main(void) {")
    if data_dict_map:
        lines.append("    __wasm_init_memory();")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("#endif")

    final_code = "\n".join(lines)

    function_name_map = []
    for func in lifted_functions:
        original_name = str(func.get("original_name")
                            or func.get("name") or "")
        llm_name = str(func.get("name") or original_name)
        function_name_map.append({
            "index": int(func.get("index", -1)),
            "wat_name": original_name,
            "llm_name": llm_name,
        })

    print(f"[Node 5] Generated {len(final_code)} chars of final C code")

    return {
        **state,
        "final_c_code": final_code,
        "function_name_map": function_name_map,
        "complete": True,
    }


def vulnerability_scanner(state):
    """
    Scan the finalized C code for security vulnerabilities using a two-pass approach.

    Pass 1 (Deep Scan): Exhaustive function-by-function audit.
    Pass 2 (Verification): Re-examine each finding to reject false positives
        and identify missed vulnerabilities (false negatives).

    Output is written to a temp directory as JSON report.

    Input: final_c_code
    Output: security_report, security_report_path
    """
    if not state.get("complete"):
        return {
            **state,
            "error_message": "Final code generation not complete",
        }

    final_c_code = state.get("final_c_code", "")
    if not final_c_code:
        return {
            **state,
            "error_message": "No final C code to scan for vulnerabilities",
        }

    config = get_decompiler_config()
    max_retries = max(1, int(config.get("llm_max_retries", 3)))
    max_prompt_tokens = max(256, int(config.get("max_prompt_tokens", 12000)))
    llm = get_chat_model(temperature=0.0)

    print("[Node 6] Pass 1/2 — Deep vulnerability scan")

    scan_prompt = ChatPromptTemplate.from_messages([
        ("system", VULN_SCANNER_SYSTEM_PROMPT),
        ("human", VULN_SCANNER_USER_TEMPLATE),
    ])
    scan_chain = scan_prompt | llm | StrOutputParser()

    scan_chunks = _split_c_code_for_llm(
        c_code=final_c_code,
        max_prompt_tokens=max_prompt_tokens,
        node_label="Node 6",
        chunk_size_cap_chars=26000,
    )
    if not scan_chunks:
        scan_chunks = [final_c_code]

    if len(scan_chunks) > 1:
        print(
            f"[Node 6] Using LangChain C chunking: {len(scan_chunks)} chunks")

    verify_prompt = ChatPromptTemplate.from_messages([
        ("system", VULN_VERIFIER_SYSTEM_PROMPT),
        ("human", VULN_VERIFIER_USER_TEMPLATE),
    ])
    verify_chain = verify_prompt | llm | StrOutputParser()

    merged: List[Dict[str, Any]] = []
    total_candidates = 0
    total_verified = 0
    total_new_findings = 0

    for idx, chunk in enumerate(scan_chunks, start=1):
        suffix = f" chunk {idx}/{len(scan_chunks)}" if len(
            scan_chunks) > 1 else ""
        try:
            raw_scan = _invoke_with_retries(
                scan_chain,
                {"final_c_code": chunk},
                max_retries=max_retries,
                node_label=f"Node 6 pass-1 deep scan{suffix}",
            )
            print(raw_scan)
            candidates = parse_vulnerability_json_array(raw_scan)
        except Exception as e:
            print(f"[Node 6] Pass 1 failed{suffix}: {e}")
            candidates = []

        print(
            f"[Node 6] Pass 1 found {len(candidates)} candidate findings{suffix}")
        total_candidates += len(candidates)
        if not candidates:
            continue

        try:
            raw_verify = _invoke_with_retries(
                verify_chain,
                {
                    "candidate_findings": json.dumps(candidates, indent=2),
                    "final_c_code": chunk,
                },
                max_retries=max_retries,
                node_label=f"Node 6 pass-2 verification{suffix}",
            )
            verified, new_findings = parse_verification_response(raw_verify)
        except Exception as e:
            print(
                f"[Node 6] Pass 2 failed{suffix}, using unverified pass-1 results: {e}")
            verified = candidates
            new_findings = []

        total_verified += len(verified)
        total_new_findings += len(new_findings)
        merged.extend(normalize_findings(verified))
        merged.extend(normalize_findings(new_findings))

    rejected_count = total_candidates - total_verified
    print(
        f"[Node 6] Verification: {total_verified} confirmed, {rejected_count} rejected, {total_new_findings} newly discovered"
    )

    deduped = deduplicate_findings(merged)
    if len(merged) != len(deduped):
        print(
            f"[Node 6] Deduplicated: {len(merged)} -> {len(deduped)} findings")

    security_report = validate_evidence(deduped, final_c_code)
    if len(deduped) != len(security_report):
        print(f"[Node 6] Evidence validation: {len(deduped)} -> {len(security_report)} "
              f"({len(deduped) - len(security_report)} rejected for fabricated evidence)")

    print(f"[Node 6] Final report: {len(security_report)} vulnerabilities")

    for i, finding in enumerate(security_report, 1):
        print(
            f"[Node 6]   {i}. [{finding.get('confidence_score', '?')}] "
            f"{finding.get('vulnerability_type', 'Unknown')}"
        )

    report_dir = write_security_report(
        security_report=security_report,
        final_c_code=final_c_code,
        input_path=state.get("wasm_path", "unknown"),
    )
    print(f"[Node 6] Full report saved to: {report_dir}")

    return {
        **state,
        "security_report": security_report,
        "security_report_path": report_dir,
        "vulnerability_scan_complete": True,
    }


def _median(values):
    """Return median for a numeric list."""
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return float(ordered[mid])
    return float((ordered[mid - 1] + ordered[mid]) / 2.0)


def _avg(values):
    """Return arithmetic mean or None for empty input."""
    if not values:
        return None
    return sum(values) / len(values)


def _as_float(value):
    """Convert a value to float when possible."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_stats_obj(stats):
    """Normalize runtime statistics into a stable JSON-serializable shape."""
    if not isinstance(stats, dict):
        return {}

    def _normalize_mapping(mapping):
        """Describe  normalize mapping."""
        if not isinstance(mapping, dict):
            return {}
        out: Dict[str, int] = {}
        for key, value in mapping.items():
            if isinstance(value, (int, float)):
                out[str(key)] = int(value)
        return out

    normalized: Dict[str, Any] = {}
    if isinstance(stats.get("instructions"), (int, float)):
        normalized["instructions"] = int(stats["instructions"])

    for section in ("blocks", "controlFlow", "calls", "numeric", "memory", "variables"):
        part = _normalize_mapping(stats.get(section))
        if part:
            normalized[section] = part

    return normalized


def _extract_dynamic_runs(dynamic_payload):
    """Extract runtime run objects from known dynamic payload shapes."""
    if not isinstance(dynamic_payload, dict):
        return []

    runs: List[Dict[str, Any]] = []
    direct_runs = dynamic_payload.get("runs")
    if isinstance(direct_runs, list):
        runs.extend(r for r in direct_runs if isinstance(r, dict))

    analysis_report = dynamic_payload.get("analysis_report")
    if isinstance(analysis_report, dict):
        report_runs = analysis_report.get("runs")
        if isinstance(report_runs, list):
            runs.extend(r for r in report_runs if isinstance(r, dict))

    return runs


def _extract_docker_samples(dynamic_payload):
    """Extract docker stats samples from known payload shapes."""
    if not isinstance(dynamic_payload, dict):
        return []

    candidates: List[Any] = [
        dynamic_payload.get("docker_stats"),
        dynamic_payload.get("stats"),
    ]

    docker_obj = dynamic_payload.get("docker")
    if isinstance(docker_obj, dict):
        candidates.append(docker_obj.get("stats"))

    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get("stats"), list):
            candidate = candidate["stats"]
        if isinstance(candidate, list):
            return [sample for sample in candidate if isinstance(sample, dict)]

    return []


def _filter_launch_spikes(values):
    """
    Drop startup warm-up samples and high outliers that are likely launch spikes.

    Returns (filtered_values, warmup_removed, outliers_removed).
    """
    if not values:
        return [], 0, 0

    total = len(values)
    if total >= 10:
        warmup_removed = max(2, int(round(total * 0.05)))
    elif total >= 4:
        warmup_removed = 1
    else:
        warmup_removed = 0

    warmup_removed = min(warmup_removed, max(0, total - 1))
    trimmed = values[warmup_removed:] if warmup_removed else list(values)
    if len(trimmed) < 4:
        return trimmed, warmup_removed, 0

    med = _median(trimmed)
    deviations = [abs(v - med) for v in trimmed]
    mad = _median(deviations)
    if mad <= 0:
        return trimmed, warmup_removed, 0

    upper = med + (6.0 * mad)
    filtered = [v for v in trimmed if v <= upper]
    outliers_removed = len(trimmed) - len(filtered)

    if not filtered:
        return trimmed, warmup_removed, 0

    return filtered, warmup_removed, outliers_removed


def _build_dynamic_analysis_context(state):
    """Build a compact dynamic-analysis context block for summary prompts."""
    dynamic_payload = state.get("dynamic_analysis")
    if not isinstance(dynamic_payload, dict) or not dynamic_payload:
        return "Unknown"

    runs = _extract_dynamic_runs(dynamic_payload)
    instruction_hits = []
    run_labels = []
    stats_snapshots: List[Dict[str, Any]] = []
    for idx, run in enumerate(runs, start=1):
        wasm_name = str(run.get("wasmFileName") or f"run_{idx}")
        stats = (((run.get("wasm") or {}).get(
            "analysisResult") or {}).get("statistics") or {})
        normalized_stats = _normalize_stats_obj(stats)
        hits = normalized_stats.get("instructions")
        if isinstance(hits, (int, float)):
            instruction_hits.append(int(hits))
            run_labels.append(f"- {wasm_name}: {int(hits)} instruction hits")
        if normalized_stats:
            stats_snapshots.append({
                "wasmFileName": wasm_name,
                "statistics": normalized_stats,
            })

    samples = _extract_docker_samples(dynamic_payload)
    cpu_values: List[float] = []
    mem_pct_values: List[float] = []
    mem_bytes_values: List[float] = []

    for sample in samples:
        cpu = _as_float(sample.get("cpu_pct"))
        mem_pct = _as_float(sample.get("mem_pct"))
        mem_bytes = _as_float(sample.get("mem_bytes"))
        if cpu is not None:
            cpu_values.append(cpu)
        if mem_pct is not None:
            mem_pct_values.append(mem_pct)
        if mem_bytes is not None:
            mem_bytes_values.append(mem_bytes)

    filtered_cpu, cpu_warmup_removed, cpu_outliers_removed = _filter_launch_spikes(
        cpu_values)
    filtered_mem_pct, mem_warmup_removed, mem_outliers_removed = _filter_launch_spikes(
        mem_pct_values)
    filtered_mem_bytes, _, _ = _filter_launch_spikes(mem_bytes_values)

    avg_cpu = _avg(filtered_cpu)
    avg_mem_pct = _avg(filtered_mem_pct)
    avg_mem_bytes = _avg(filtered_mem_bytes)

    lines: List[str] = [
        "Use this runtime telemetry as supporting evidence.",
        "Treat startup browser-launch spikes as false positives; rely on filtered averages below.",
        f"Instruction hit count (sum across runs): {sum(instruction_hits) if instruction_hits else 'Unknown'}",
    ]
    if run_labels:
        lines.append("Instruction hits per run:")
        lines.extend(run_labels)
    if stats_snapshots:
        lines.append("Per-run WASM statistics (from analysis_report.json):")
        max_stats_runs = 5
        for snapshot in stats_snapshots[:max_stats_runs]:
            lines.append(json.dumps(snapshot, indent=2, ensure_ascii=True))
        omitted = len(stats_snapshots) - max_stats_runs
        if omitted > 0:
            lines.append(
                f"... omitted statistics for {omitted} additional run(s)")

    lines.append(f"CPU samples: {len(cpu_values)} total")
    lines.append(
        "CPU filtering applied: "
        f"removed {cpu_warmup_removed} warm-up sample(s), {cpu_outliers_removed} launch-spike outlier(s)"
    )
    lines.append(
        f"Average CPU usage (filtered): {avg_cpu:.2f}%" if avg_cpu is not None else "Average CPU usage (filtered): Unknown")
    lines.append(
        f"Peak CPU usage (raw): {max(cpu_values):.2f}%" if cpu_values else "Peak CPU usage (raw): Unknown")

    lines.append(f"Memory samples: {len(mem_pct_values)} total")
    lines.append(
        "Memory filtering applied: "
        f"removed {mem_warmup_removed} warm-up sample(s), {mem_outliers_removed} launch-spike outlier(s)"
    )
    lines.append(
        f"Average memory usage (filtered): {avg_mem_pct:.2f}%"
        if avg_mem_pct is not None else "Average memory usage (filtered): Unknown"
    )
    lines.append(
        f"Average memory usage (filtered bytes): {avg_mem_bytes / (1024 * 1024):.2f} MiB"
        if avg_mem_bytes is not None else "Average memory usage (filtered bytes): Unknown"
    )
    lines.append(
        f"Peak memory usage (raw): {max(mem_pct_values):.2f}%"
        if mem_pct_values else "Peak memory usage (raw): Unknown"
    )

    return "\n".join(lines)


def summarize_output(state):
    """
    Generate a natural-language summary of the whole decompiled program.

    Input: final_c_code
    Output: final_summary
    """
    if not state.get("complete"):
        return {
            **state,
            "error_message": "Final code generation not complete",
        }

    final_c_code = state.get("final_c_code", "")
    if not final_c_code:
        return {
            **state,
            "error_message": "No final C code to summarize",
        }

    config = get_decompiler_config()
    print("[Node 7] Summarizing decompiled program")
    dynamic_analysis_context = _build_dynamic_analysis_context(state)

    try:
        llm = get_chat_model(temperature=0.0)
        prompt = ChatPromptTemplate.from_messages([
            ("system", SUMMARY_SYSTEM_PROMPT),
            ("human", SUMMARY_USER_TEMPLATE),
        ])
        chain = prompt | llm | StrOutputParser()

        max_retries = max(1, int(config.get("llm_max_retries", 3)))
        summary = _invoke_with_retries(
            chain,
            {
                "final_c_code": final_c_code,
                "dynamic_analysis_context": dynamic_analysis_context,
            },
            max_retries=max_retries,
            node_label="Node 7 summarize output",
        )

        return {
            **state,
            "final_summary": summary.strip(),
        }
    except Exception as e:
        return {
            **state,
            "error_message": f"Failed to summarize output: {e}",
        }


__all__ = [
    "parse_wat",
    "summarize_symbols",
    "lift_functions",
    "refine_code",
    "finalize_output",
    "vulnerability_scanner",
    "summarize_output",
]
