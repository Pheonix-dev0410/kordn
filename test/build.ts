import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

// Vitest global setup: one build before all test files, never during them.
export default function build(): void {
  execFileSync('npm', ['run', 'build', '--silent'], { cwd: resolve(import.meta.dirname, '..'), stdio: 'inherit' });
}
