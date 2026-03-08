import re
import os
import subprocess
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class WatFunction:

    index: int
    name: Optional[str] = None
    params: List[Tuple[str, str]] = field(default_factory=list)
    locals: List[Tuple[str, str]] = field(default_factory=list)
    result_type: Optional[str] = None
    body: str = ""
    raw: str = ""
    dfg: Optional[str] = None
    call_graph: Optional[str] = None

    def to_chunk(self):
        """Format function for LLM consumption."""
        lines = []
        lines.append(f"--- FUNCTION #{self.index} ---")
        if self.name:
            lines.append(f"Name: {self.name}")
        if self.params:
            params_str = ", ".join(f"{n}: {t}" for n, t in self.params)
            lines.append(f"Params: ({params_str})")
        if self.result_type:
            lines.append(f"Returns: {self.result_type}")
        if self.locals:
            locals_str = ", ".join(f"{n}: {t}" for n, t in self.locals)
            lines.append(f"Locals: ({locals_str})")

        lines.append("\n[WAT Code]")
        lines.append(self.raw)

        if self.dfg:
            lines.append("\n[Data Flow Graph]")
            lines.append(self.dfg)

        if self.call_graph:
            lines.append("\n[Call Graph]")
            lines.append(self.call_graph)

        return "\n".join(lines)


@dataclass
class WatDataSection:

    offset: Optional[int] = None
    offset_expr: str = ""
    content: str = ""
    raw_bytes: bytes = field(default_factory=bytes)
    memory_index: int = 0
    is_passive: bool = False
    raw: str = ""


@dataclass
class WatModule:

    functions: List[WatFunction] = field(default_factory=list)
    data_sections: List[WatDataSection] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    memories: List[str] = field(default_factory=list)
    globals: List[str] = field(default_factory=list)
    tables: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)
    raw_header: str = ""

    def get_data_dictionary(self):
        """Return offset -> string mapping for LLM context (only for active segments with known offsets)."""
        return {d.offset: d.content for d in self.data_sections if d.offset is not None}

    def get_data_summary(self):
        """Return a human-readable summary of all data sections."""
        lines = []
        for i, d in enumerate(self.data_sections):
            if d.is_passive:
                loc = "passive"
            elif d.offset is not None:
                loc = f"offset {d.offset} (0x{d.offset:x})"
            else:
                loc = f"expr: {d.offset_expr}"

            content_preview = d.content[:60] + \
                "..." if len(d.content) > 60 else d.content
            content_preview = repr(content_preview)

            lines.append(f"  [{i}] {loc}: {content_preview}")

        return "\n".join(lines) if lines else "  (none)"


class WatParser:

    DEFAULT_WASP_BIN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "ext-binary", "wasp"
    )

    def __init__(self, wasp_bin=None):
        """
        Initialize the WAT parser.

        Args:
            wasp_bin: Path to WASP binary for DFG/Call Graph analysis (optional).
                     If None, uses default path at ext-binary/wasp
        """
        if wasp_bin is None:

            if os.path.exists(self.DEFAULT_WASP_BIN):
                self.wasp_bin = self.DEFAULT_WASP_BIN
            else:
                self.wasp_bin = None
        else:
            self.wasp_bin = wasp_bin

    def parse_file(self, wat_path, wasm_path=None):
        """
        Parse a WAT file into a structured WatModule.

        Args:
            wat_path: Path to .wat file
            wasm_path: Path to original .wasm file (for WASP analysis)

        Returns:
            WatModule with parsed functions, data sections, etc.
        """
        with open(wat_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return self.parse_content(content, wasm_path)

    def parse_content(self, content, wasm_path=None):
        """
        Parse WAT content string into a structured WatModule.

        Args:
            content: WAT source code
            wasm_path: Path to original .wasm file (for WASP analysis)

        Returns:
            WatModule with parsed functions, data sections, etc.
        """
        module = WatModule()

        blocks = self._parse_sexp_blocks(content)

        if len(blocks) == 1 and blocks[0].strip().startswith('(module'):
            inner = self._unwrap_module(blocks[0])
            blocks = self._parse_sexp_blocks(inner)

        if wasm_path and os.path.exists(wasm_path):
            func_index = self._get_first_func_index(wasm_path)
        else:
            imported_function_count = sum(
                1 for block in blocks
                if self._get_block_type(block) == 'import' and self._is_function_import(block)
            )
            func_index = imported_function_count
        header_parts = []

        for block in blocks:
            block_type = self._get_block_type(block)

            if block_type == 'func':
                func = self._parse_function(block, func_index)
                module.functions.append(func)
                func_index += 1
            elif block_type == 'data':
                data = self._parse_data_section(block)
                if data:
                    module.data_sections.append(data)
                header_parts.append(block)
            elif block_type == 'import':
                module.imports.append(block)
                header_parts.append(block)
            elif block_type == 'export':
                module.exports.append(block)
                header_parts.append(block)
            elif block_type == 'memory':
                module.memories.append(block)
                header_parts.append(block)
            elif block_type == 'global':
                module.globals.append(block)
                header_parts.append(block)
            elif block_type == 'table':
                module.tables.append(block)
                header_parts.append(block)
            elif block_type == 'type':
                module.types.append(block)
                header_parts.append(block)
            else:
                header_parts.append(block)

        module.raw_header = "\n".join(header_parts)

        if self.wasp_bin and wasm_path and os.path.exists(wasm_path):
            self._enrich_with_wasp(module, wasm_path)

        return module

    def _is_function_import(self, block):
        """Return True if an import block imports a function."""

        return bool(re.search(r'\(\s*func\b', block))

    def _parse_sexp_blocks(self, content):
        """
        Extract all top-level S-expressions from content.
        Handles nested brackets and strings correctly.
        """
        blocks = []
        depth = 0
        start_index = -1
        in_string = False
        in_comment = False

        i = 0
        while i < len(content):
            char = content[i]

            if not in_string and char == ';' and i + 1 < len(content) and content[i + 1] == ';':

                while i < len(content) and content[i] != '\n':
                    i += 1
                continue

            if not in_string and char == ';' and i + 1 < len(content) and content[i + 1] != ';':

                pass

            if char == '"' and (i == 0 or content[i - 1] != '\\'):
                in_string = not in_string
                i += 1
                continue

            if in_string:
                i += 1
                continue

            if char == '(':
                if depth == 0:
                    start_index = i
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0 and start_index != -1:
                    blocks.append(content[start_index:i + 1])
                    start_index = -1

            i += 1

        return blocks

    def _unwrap_module(self, module_sexp):
        """Remove the outer (module ...) wrapper."""

        match = re.match(r'\(\s*module\s*', module_sexp)
        if match:
            inner_start = match.end()

            return module_sexp[inner_start:-1]
        return module_sexp

    def _get_block_type(self, block):
        """Identify the type of a WAT S-expression block."""
        block = block.strip()
        patterns = [
            (r'^\(\s*func\b', 'func'),
            (r'^\(\s*data\b', 'data'),
            (r'^\(\s*import\b', 'import'),
            (r'^\(\s*export\b', 'export'),
            (r'^\(\s*memory\b', 'memory'),
            (r'^\(\s*global\b', 'global'),
            (r'^\(\s*table\b', 'table'),
            (r'^\(\s*type\b', 'type'),
            (r'^\(\s*elem\b', 'elem'),
            (r'^\(\s*start\b', 'start'),
        ]
        for pattern, block_type in patterns:
            if re.match(pattern, block):
                return block_type
        return 'unknown'

    def _parse_function(self, block, index):
        """Parse a function S-expression into WatFunction."""
        func = WatFunction(index=index, raw=block)

        name_match = re.search(r'\(\s*func\s+(\$[\w_]+)', block)
        if name_match:
            func.name = name_match.group(1)

        export_match = re.search(r'\(\s*export\s+"([^"]+)"\s*\)', block)
        if export_match:
            func.name = export_match.group(1)

        param_pattern = re.compile(
            r'\(\s*param\s+(?:(\$[\w_]+)\s+)?(\w+)\s*\)')
        for match in param_pattern.finditer(block):
            name = match.group(1) or f"$arg{len(func.params)}"
            ptype = match.group(2)
            func.params.append((name, ptype))

        result_match = re.search(r'\(\s*result\s+(\w+)\s*\)', block)
        if result_match:
            func.result_type = result_match.group(1)

        local_pattern = re.compile(
            r'\(\s*local\s+(?:(\$[\w_]+)\s+)?(\w+)\s*\)')
        for match in local_pattern.finditer(block):
            name = match.group(1) or f"$local{len(func.locals)}"
            ltype = match.group(2)
            func.locals.append((name, ltype))

        func.body = block

        return func

    def _parse_data_section(self, block):
        """
        Parse a data section S-expression.

        Handles various formats:
        - Active: (data (memory $mem) (offset (i32.const N)) "...")
        - Active: (data (i32.const N) "...")
        - Active: (data (global.get $g) "...")
        - Passive: (data "...")
        - Multi-memory: (data $memidx (offset ...) "...")
        """
        data = WatDataSection(raw=block)

        mem_match = re.search(
            r'\(\s*memory\s+(?:(\$[\w_]+)|(\d+))\s*\)', block)
        if mem_match:
            mem_id = mem_match.group(1) or mem_match.group(2)
            if mem_id and mem_id.isdigit():
                data.memory_index = int(mem_id)

        offset_wrapper = re.search(r'\(\s*offset\s+(\([^)]+\))\s*\)', block)
        if offset_wrapper:
            data.offset_expr = offset_wrapper.group(1).strip()
        else:

            direct_offset = re.search(
                r'\(\s*(i32\.const|i64\.const|f32\.const|f64\.const|global\.get)\s+([^\s)]+)\s*\)',
                block
            )
            if direct_offset:
                data.offset_expr = f"({direct_offset.group(1)} {direct_offset.group(2)})"

        if data.offset_expr:
            data.is_passive = False

            const_match = re.search(
                r'(?:i32|i64|f32|f64)\.const\s+(-?\d+)', data.offset_expr)
            if const_match:
                data.offset = int(const_match.group(1))

            hex_match = re.search(
                r'(?:i32|i64|f32|f64)\.const\s+(0x[0-9a-fA-F]+)', data.offset_expr)
            if hex_match:
                data.offset = int(hex_match.group(1), 16)
        else:

            data.is_passive = True

        string_parts = []
        raw_bytes = bytearray()

        i = 0
        while i < len(block):
            if block[i] == '"':

                j = i + 1
                current_str = ""
                while j < len(block):
                    if block[j] == '\\' and j + 1 < len(block):

                        next_char = block[j + 1]
                        if next_char == '"':
                            current_str += '"'
                            j += 2
                        elif next_char == '\\':
                            current_str += '\\'
                            j += 2
                        elif next_char == 'n':
                            current_str += '\n'
                            j += 2
                        elif next_char == 't':
                            current_str += '\t'
                            j += 2
                        elif next_char == 'r':
                            current_str += '\r'
                            j += 2
                        elif next_char in '0123456789abcdefABCDEF':

                            if j + 2 < len(block) and block[j + 2] in '0123456789abcdefABCDEF':
                                hex_val = block[j + 1:j + 3]
                                byte_val = int(hex_val, 16)
                                raw_bytes.append(byte_val)

                                if 32 <= byte_val < 127:
                                    current_str += chr(byte_val)
                                else:
                                    current_str += f'\\x{hex_val}'
                                j += 3
                            else:
                                current_str += block[j:j + 2]
                                j += 2
                        else:
                            current_str += block[j:j + 2]
                            j += 2
                    elif block[j] == '"':

                        string_parts.append(current_str)
                        i = j
                        break
                    else:
                        current_str += block[j]
                        if ord(block[j]) < 128:
                            raw_bytes.append(ord(block[j]))
                        j += 1
            i += 1

        if string_parts:
            data.content = "".join(string_parts)
            data.raw_bytes = bytes(raw_bytes)
            return data

        return data if data.offset_expr or data.is_passive else None

    def _unescape_wat_string(self, s):
        """Unescape WAT string literals."""

        def hex_replace(m):
            """Describe hex replace."""
            return chr(int(m.group(1), 16))
        s = re.sub(r'\\([0-9a-fA-F]{2})', hex_replace, s)

        s = s.replace('\\n', '\n')
        s = s.replace('\\t', '\t')
        s = s.replace('\\r', '\r')
        s = s.replace('\\"', '"')
        s = s.replace('\\\\', '\\')
        return s

    def _get_first_func_index(self, wasm_path):
        """Get the first function index using wasm-objdump -x."""
        try:
            result = subprocess.run(
                ["wasm-objdump", "-x", wasm_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return 0

            in_func_section = False
            for line in result.stdout.split('\n'):
                if line.startswith("Function["):
                    in_func_section = True
                    continue
                if in_func_section and line.strip().startswith("- func["):
                    match = re.match(r'\s*- func\[(\d+)\]', line)
                    if match:
                        return int(match.group(1))
                elif in_func_section and line and not line.startswith(" "):
                    break
            return 0
        except Exception:
            return 0

    def _enrich_with_wasp(self, module, wasm_path):
        """Add DFG/Call Graph analysis from WASP to functions."""
        if not self.wasp_bin or not os.path.exists(self.wasp_bin):
            return

        for func in module.functions:
            func.dfg = self._run_wasp('dfg', func.index, wasm_path)
            func.call_graph = self._run_wasp(
                'callgraph', func.index, wasm_path)

    def _run_wasp(self, mode, func_id, wasm_path):
        """Run WASP to get DFG or callgraph."""
        try:
            cmd = [self.wasp_bin, mode]
            if mode == 'dfg':
                cmd.extend(['-f', str(func_id)])
            elif mode == 'callgraph':
                cmd.extend(['--calls', str(func_id)])
            cmd.append(wasm_path)

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                graph = self._extract_digraph(result.stdout)
                return graph
        except Exception as e:
            pass

        return None

    def _extract_digraph(self, output):
        """Extract DOT digraph from WASP output."""
        start_marker = "strict digraph"
        start_pos = output.find(start_marker)

        if start_pos == -1:
            return None

        open_brace = output.find('{', start_pos)
        if open_brace == -1:
            return None

        depth = 0
        in_string = False

        for i in range(open_brace, len(output)):
            char = output[i]

            if char == '"' and (i == 0 or output[i - 1] != '\\'):
                in_string = not in_string
                continue

            if in_string:
                continue

            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return output[start_pos:i + 1]

        return None


def _estimate_tokens_wat(text):
    """Rough token estimate using character count (conservative heuristic)."""
    if not text:
        return 0
    return int(len(text) / 3.6) + 8


def _paren_delta_outside_strings(line):
    """Count parenthesis delta while ignoring quoted strings and escaped chars."""
    delta = 0
    in_string = False
    escape = False
    for ch in line:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "\"":
                in_string = False
            continue
        if ch == "\"":
            in_string = True
        elif ch == "(":
            delta += 1
        elif ch == ")":
            delta -= 1
    return delta


def split_wat_top_level_units(func_raw):
    """
    Split a WAT function into top-level units, preserving block boundaries.

    Units are contiguous line groups that end when paren depth returns to
    function top-level depth (1). This avoids cutting in the middle of nested
    `block/loop/if` structures.
    """
    lines = (func_raw or "").splitlines()
    if len(lines) <= 2:
        return [func_raw.strip()] if func_raw.strip() else []

    units: List[str] = []
    cur: List[str] = []
    depth = _paren_delta_outside_strings(lines[0])
    for line in lines[1:]:
        cur.append(line)
        depth += _paren_delta_outside_strings(line)
        if depth == 1:
            units.append("\n".join(cur))
            cur = []
        if depth <= 0:
            break

    if cur:
        units.append("\n".join(cur))
    return units


def build_function_structure_hint(func_raw, max_lines=160):
    """
    Build a concise structural outline for a large function.

    Captures declaration and control-flow lines (`local`, `if`, `loop`, `block`)
    without copying the full body.
    """
    lines: List[str] = []
    for raw in (func_raw or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("(func"):
            lines.append(line)
            continue
        if line.startswith("(local") or line.startswith("local."):
            lines.append(line)
            continue
        if line.startswith("(if") or line.startswith("if"):
            lines.append(line)
            continue
        if line.startswith("(loop") or line.startswith("loop"):
            lines.append(line)
            continue
        if line.startswith("(block") or line.startswith("block"):
            lines.append(line)
            continue
        if line.startswith(")"):
            lines.append(line)

    if not lines:
        return "(structure unavailable)"
    if len(lines) > max_lines:
        keep_head = int(max_lines * 0.7)
        keep_tail = max(1, int(max_lines * 0.3))
        merged = lines[:keep_head] + \
            ["... [structure truncated] ..."] + lines[-keep_tail:]
        return "\n".join(merged)
    return "\n".join(lines)


def split_wat_function_inner_blocks(func_raw, max_prompt_tokens):
    """
    Split a large WAT function into smaller semantic blocks for fallback lifting.

    Uses depth-aware top-level unit extraction and recursively descends when
    a block is still too large.
    """
    source = (func_raw or "").strip()
    if not source:
        return []

    block_budget = max(128, int(max_prompt_tokens * 0.6))
    if _estimate_tokens_wat(source) <= block_budget:
        return [source]

    units = split_wat_top_level_units(source)
    if not units:
        return _split_wat_lines_by_budget(source, block_budget)

    pieces: List[str] = []
    for unit in units:
        pieces.extend(_split_wat_block_recursive(unit, block_budget, depth=0))

    return [p for p in pieces if p and p.strip()]


def _split_wat_block_recursive(block, block_budget, depth):
    """Recursively split oversized WAT block into bounded inner blocks."""
    if _estimate_tokens_wat(block) <= block_budget:
        return [block]

    if depth >= 5:
        return _split_wat_lines_by_budget(block, block_budget)

    subunits = split_wat_top_level_units(block)
    if not subunits or len(subunits) <= 1:
        return _split_wat_lines_by_budget(block, block_budget)

    parts: List[str] = []
    for sub in subunits:
        parts.extend(_split_wat_block_recursive(sub, block_budget, depth + 1))
    return parts


def _split_wat_lines_by_budget(text, block_budget):
    """
    Final fallback splitter by line budget.

    Keeps lines contiguous to preserve local execution context.
    """
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return []

    chunks: List[str] = []
    cur: List[str] = []
    cur_tokens = 0
    for line in lines:
        line_tokens = _estimate_tokens_wat(line) + 1
        if cur and (cur_tokens + line_tokens) > block_budget:
            chunks.append("\n".join(cur))
            cur = []
            cur_tokens = 0
        cur.append(line)
        cur_tokens += line_tokens
    if cur:
        chunks.append("\n".join(cur))
    return chunks


def wasm_to_wat(wasm_path, wat_path=None):
    """
    Convert WASM binary to WAT text format using wasm2wat.

    Args:
        wasm_path: Path to .wasm file
        wat_path: Output path for .wat file (optional, defaults to same name)

    Returns:
        Path to the generated .wat file
    """
    if wat_path is None:
        wat_path = os.path.splitext(wasm_path)[0] + ".wat"

    try:
        subprocess.run(
            ["wasm2wat", wasm_path, "-o", wat_path],
            check=True,
            capture_output=True
        )
    except FileNotFoundError:
        raise RuntimeError(
            "wasm2wat not found. Install wabt: sudo apt install wabt")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wasm2wat failed: {e.stderr.decode()}")

    return wat_path


def parse_wat(path, wasp_bin=None):
    """
    Parse a WAT or WASM file into a WatModule.

    Args:
        path: Path to .wat or .wasm file
        wasp_bin: Path to WASP binary (optional)

    Returns:
        Parsed WatModule
    """
    wasm_path = None

    if path.endswith('.wasm'):
        wasm_path = path
        wat_path = wasm_to_wat(wasm_path)
    else:
        wat_path = path

        potential_wasm = os.path.splitext(path)[0] + ".wasm"
        if os.path.exists(potential_wasm):
            wasm_path = potential_wasm

    parser = WatParser(wasp_bin=wasp_bin)
    return parser.parse_file(wat_path, wasm_path)
