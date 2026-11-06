import { spawn } from 'node:child_process';

export async function runCommand(command, args, { env, cwd, signal, timeout = 20 * 60 * 1000 }) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: 'ignore', detached: true });
    let interrupted = false;
    let hardKill;
    const kill = name => { try { process.kill(-child.pid, name); } catch {} };
    const stop = () => {
      interrupted = true;
      kill('SIGTERM');
      hardKill ??= setTimeout(() => kill('SIGKILL'), 5000);
    };
    const timer = setTimeout(stop, timeout);
    signal.addEventListener('abort', stop, { once: true });
    if (signal.aborted) stop();
    const cleanup = () => { clearTimeout(timer); clearTimeout(hardKill); signal.removeEventListener('abort', stop); };
    child.once('error', () => { cleanup(); reject(new Error('Cannot start updater subprocess')); });
    child.once('close', code => {
      cleanup();
      if (interrupted) kill('SIGKILL');
      if (interrupted) reject(new Error('Updater subprocess interrupted or timed out'));
      else if (code !== 0) reject(new Error(`Updater subprocess failed (exit ${code})`));
      else resolve();
    });
  });
}
