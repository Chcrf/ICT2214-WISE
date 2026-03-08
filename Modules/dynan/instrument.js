// instrument.js
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function instrumentWasm(wasmBytes) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wasabi-'));
  const inputPath = path.join(tmpDir, 'input.wasm');
  const outputPath = path.join(tmpDir, 'out', 'input.wasm');
  const gluePath = path.join(tmpDir, 'out', 'input.wasabi.js');

  fs.writeFileSync(inputPath, wasmBytes);

  try {
    execFileSync('wasabi', ['input.wasm'], { cwd: tmpDir, stdio: 'pipe' });
    
    // Return both the binary and the generated JS runtime
    const binary = fs.readFileSync(outputPath);
    const glue = fs.readFileSync(gluePath, 'utf8');
    
    fs.rmSync(tmpDir, { recursive: true, force: true });
    return { binary, glue };
  } catch (err) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    throw err;
  }
}

module.exports = { instrumentWasm };