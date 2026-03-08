// Author: Michael Pradel (Original) | Refined for Ordered Trace
/*
 * Wasabi Analysis - Ordered Trace
 * Preserves the exact sequence of calls (Timeline).
 */

(function() {

    console.log("Starting analysis... Results in Wasabi.analysisResult.trace");

    // --- 1. Data Structures ---

    // Array to hold the ordered history of calls
    const trace = []; 
    
    let callDepth = 0;

    const counters = {
        instructions: 0,
        blocks: { start: 0, end: 0, loop: 0, block: 0, if: 0 },
        controlFlow: {
            if: 0, br: 0, br_if: 0, br_table: 0, 
            unreachable: 0, nop: 0, select: 0, 
            return: 0, drop: 0
        },
        calls: { direct: 0, indirect: 0, returns: 0 },
        numeric: {
            const: 0, unary: 0, binary: 0,
            bitwiseOps: 0,    
            suspiciousUnary: 0 
        },
        memory: { load: 0, store: 0, size: 0, grow: 0 },
        variables: {
            local_get: 0, local_set: 0, local_tee: 0,
            global_get: 0, global_set: 0
        }
    };

    Wasabi.analysisResult = {
        trace: trace, // <--- Access this for the ordered list
        statistics: counters
    };

    // --- 2. Helper Functions ---

    function fctName(fctId) {
        const fct = Wasabi.module.info.functions[fctId];
        if (fct.export[0] !== undefined) return fct.export[0];
        if (fct.import !== null) return fct.import;
        return fctId; 
    }

    function isBitwise(op) {
        return op.includes("xor") || op.includes("and") || op.includes("or") || 
               op.includes("shl") || op.includes("shr") || op.includes("rot");
    }

    // --- 3. Analysis Hooks ---

    Wasabi.analysis = {
        
        start(location) { 
        },

        // Standard Operation Counting
        nop(location) { counters.instructions++; counters.controlFlow.nop++; },
        unreachable(location) { counters.instructions++; counters.controlFlow.unreachable++; },
        if_(location, condition) { counters.instructions++; counters.controlFlow.if++; },
        br(location, target) { counters.instructions++; counters.controlFlow.br++; },
        br_if(location, conditionalTarget, condition) { counters.instructions++; counters.controlFlow.br_if++; },
        br_table(location, table, defaultTarget, tableIdx) { counters.instructions++; counters.controlFlow.br_table++; },
        begin(location, type) {
            counters.instructions++; 
            counters.blocks.start++;
            if (counters.blocks[type] !== undefined) counters.blocks[type]++;
        },
        end(location, type, beginLocation, ifLocation) { counters.instructions++; counters.blocks.end++; },
        drop(location, value) { counters.instructions++; counters.controlFlow.drop++; },
        select(location, cond, first, second) { counters.instructions++; counters.controlFlow.select++; },
        return_(location, values) { counters.instructions++; counters.controlFlow.return++; },

        // --- ORDERED TRACE LOGGING ---
        call_pre(location, targetFunc, args, indirectTableIdx) {
            counters.instructions++;
            
            const caller = fctName(location.func);
            const callee = fctName(targetFunc);
            
            // Convert BigInts to strings
            const safeArgs = args.map(arg => 
                typeof arg === 'bigint' ? arg.toString() : arg
            );

            // Create the structured event object
            const callEvent = {
                signature: `${caller} -> ${callee}`,
                depth: callDepth,
                args: safeArgs
            };

            // Add to the timeline
            // Safety: Keep last 5000 events to prevent crash
            if (trace.length > 5000) {
                trace.shift();
            }
            trace.push(callEvent);

            // Stats
            if (indirectTableIdx === undefined) counters.calls.direct++;
            else counters.calls.indirect++;

            // Increment Depth
            callDepth++;
        },

        call_post(location, values) {
            counters.calls.returns++;
            // Decrease Depth
            if (callDepth > 0) callDepth--;
        },

        const_(location, op, value) { counters.instructions++; counters.numeric.const++; },
        unary(location, op, input, result) {
            counters.instructions++;
            counters.numeric.unary++;
            if (op.includes("popcnt") || op.includes("clz") || op.includes("ctz")) {
                counters.numeric.suspiciousUnary++;
            }
        },
        binary(location, op, first, second, result) {
            counters.instructions++;
            counters.numeric.binary++;
            if (isBitwise(op)) counters.numeric.bitwiseOps++;
        },

        load(location, op, memarg, value) { counters.instructions++; counters.memory.load++; },
        store(location, op, memarg, value) { counters.instructions++; counters.memory.store++; },
        memory_size(location, currentSizePages) { counters.instructions++; counters.memory.size++; },
        memory_grow(location, byPages, previousSizePages) { counters.instructions++; counters.memory.grow++; },

        local(location, op, localIndex, value) {
            counters.instructions++;
            if (op === "local.get") counters.variables.local_get++;
            if (op === "local.set") counters.variables.local_set++;
            if (op === "local.tee") counters.variables.local_tee++;
        },
        global(location, op, globalIndex, value) {
            counters.instructions++;
            if (op === "global.get") counters.variables.global_get++;
            if (op === "global.set") counters.variables.global_set++;
        }
    };

})();