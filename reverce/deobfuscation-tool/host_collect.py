"""Live Frida host collector; writes JSONL messages without altering them."""
import argparse
import json
import threading
import typing
from pathlib import Path

def ensure_typing_compat():
    missing = [name for name in ('NotRequired', 'ParamSpec') if not hasattr(typing, name)]
    if missing:
        import typing_extensions
        for name in missing:
            setattr(typing, name, getattr(typing_extensions, name))

def main():
    p = argparse.ArgumentParser(); p.add_argument('--device', required=True); p.add_argument('--pid', type=int, required=True); p.add_argument('--script', required=True); p.add_argument('--output', required=True); p.add_argument('--module', required=True); p.add_argument('--symbol', required=True); p.add_argument('--run-id', required=True)
    a = p.parse_args()
    ensure_typing_compat()
    import frida
    done = threading.Event(); failed = threading.Event()
    device = frida.get_device_manager().add_remote_device(a.device); session = device.attach(a.pid); session.on('detached', lambda *x: done.set())
    with Path(a.output).open('x', encoding='utf-8') as f:
        def message(msg, data):
            if msg['type'] == 'send':
                f.write(json.dumps(msg['payload']) + '\n'); f.flush()
            else:
                f.write(json.dumps({'type':'error', 'reason': str(msg)}) + '\n'); f.flush()
                failed.set(); done.set()
        script = session.create_script(Path(a.script).read_text(encoding='utf-8')); script.on('message', message); script.load()
        script.exports_sync.configure(a.module, a.symbol, a.run_id)
        try: done.wait()
        except KeyboardInterrupt: pass
        finally: session.detach()
        if failed.is_set(): raise SystemExit('Frida script error; capture is invalid')
if __name__ == '__main__': main()
