from __future__ import annotations

import argparse
import os
import signal
import subprocess as sp
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

# caminhos base do projeto
BASE = Path(__file__).parent.resolve()
SERVER = BASE / "server.py"
CLIENT = BASE / "client.py"
SHARED = BASE / "shared"
DOWNLOADS = BASE / "downloads"
LOGDIR = BASE / "logs"

PY = sys.executable


# ---------------------- utilidades ----------------------
def ensure_dirs():
    """cria pastas padrão (shared, downloads, logs) se não existirem"""
    SHARED.mkdir(exist_ok=True)
    DOWNLOADS.mkdir(exist_ok=True)
    LOGDIR.mkdir(exist_ok=True)


def sha256_path(path: Path) -> str:
    """calcula sha-256 de um arquivo e retorna hexdigest"""
    import hashlib

    BUF = 1024 * 1024
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(BUF)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_test_file(path: Path, size_mb: int):
    """gera arquivo aleatório com tamanho mínimo informado (mb)"""
    if path.exists() and path.stat().st_size >= size_mb * 1024 * 1024:
        return
    print(f"[TB] Gerando arquivo de {size_mb} MB: {path}")
    with open(path, "wb") as f:
        remain = size_mb * 1024 * 1024
        while remain > 0:
            chunk = os.urandom(min(remain, 1024 * 1024))
            f.write(chunk)
            remain -= len(chunk)


def mbps(size_bytes: int, secs: float) -> float:
    """converte bytes e tempo em mb/s"""
    if secs <= 0:
        return 0.0
    return (size_bytes / (1024 * 1024)) / secs


def parse_list_ints(s: str) -> List[int]:
    """transforma string '1,2,3' em lista de inteiros"""
    if not s:
        return []
    return [int(x.strip()) for x in s.split(",") if x.strip()]


def parse_list_str(s: str) -> List[str]:
    """transforma string separada por vírgulas em lista de strings"""
    return [x.strip() for x in s.split(",") if x.strip()]


# ---------------------- servidor ----------------------
def start_server(
    port: int, shared_dir: Path, pace_every: int = 50, pace_sleep: float = 0.001
) -> Tuple[sp.Popen, Path]:
    """inicia o servidor em subprocesso e retorna (proc, log_path)"""
    log = LOGDIR / f"server_p{port}.log"
    print(f"[TB] Iniciando servidor em 0.0.0.0:{port} (log: {log.name})")
    print(f"[TB] Pacing: {pace_every} pacotes, pausa {pace_sleep}s")
    f = open(log, "w", buffering=1, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    cmd = [
        PY,
        "-u",
        str(SERVER),
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
        "--shared",
        str(shared_dir),
        "--pace-every",
        str(pace_every),
        "--pace-sleep",
        str(pace_sleep),
    ]
    proc = sp.Popen(cmd, cwd=str(BASE), stdout=f, stderr=sp.STDOUT, env=env)
    time.sleep(1.0)  # pequena espera para o bind
    return proc, log


def stop_server(proc: sp.Popen):
    """tenta encerrar o servidor com term/sigint e aguarda"""
    if proc.poll() is not None:
        return
    print("[TB] Encerrando servidor...")
    try:
        if os.name == "nt":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGINT)
    except Exception:
        pass
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()


# ---------------------- execuções de cliente ----------------------
def run_client(
    server: str,
    port: int,
    req_path: str,
    out_path: Path,
    *,
    drop_seq: List[int],
    drop_rate: float,
    label: str,
) -> Tuple[int, float, float, Path]:
    """executa o cliente e retorna (retcode, tempo, mb/s, log_path)"""
    log = LOGDIR / f"client_{label}.log"
    if out_path.exists():
        try:
            out_path.unlink()
        except Exception:
            pass
    cmd = [
        PY,
        str(CLIENT),
        "--server",
        server,
        "--port",
        str(port),
        "--path",
        req_path,
        "--out",
        str(out_path),
    ]
    if drop_seq:
        cmd += ["--drop", ",".join(str(x) for x in drop_seq)]
    if drop_rate > 0:
        cmd += ["--drop-rate", str(drop_rate)]
    size_bytes = (
        (SHARED / req_path.lstrip("/")).stat().st_size
        if (SHARED / req_path.lstrip("/")).exists()
        else 0
    )
    t0 = time.perf_counter()
    with open(log, "w", buffering=1, encoding="utf-8") as lf:
        ret = sp.call(cmd, cwd=str(BASE), stdout=lf, stderr=sp.STDOUT)
    t1 = time.perf_counter()
    secs = t1 - t0
    thr = mbps(size_bytes, secs) if size_bytes > 0 else 0.0
    return ret, secs, thr, log


# ---------------------- casos ----------------------
def case_normal(
    server: str,
    port: int,
    file_rel: str,
    out_rel: str,
    drop_seq: List[int],
    drop_rate: float,
) -> Dict[str, str]:
    """caso base: 1 cliente, parâmetros repassados"""
    label = "normal"
    out = DOWNLOADS / out_rel
    ret, secs, thr, log = run_client(
        server, port, file_rel, out, drop_seq=drop_seq, drop_rate=drop_rate, label=label
    )
    ok = False
    if ret == 0 and out.exists():
        ok = sha256_path(SHARED / file_rel.lstrip("/")) == sha256_path(out)
    return {
        "case": label,
        "ret": str(ret),
        "secs": f"{secs:.3f}",
        "mbps": f"{thr:.3f}",
        "ok": "1" if ok else "0",
        "log": log.name,
    }


def case_missing(server: str, port: int) -> Dict[str, str]:
    """caso de arquivo inexistente (espera falha)"""
    label = "missing"
    out = DOWNLOADS / "inexistente.bin"
    ret, secs, thr, log = run_client(
        server,
        port,
        "/arquivo_que_nao_existe.xyz",
        out,
        drop_seq=[],
        drop_rate=0.0,
        label=label,
    )
    return {
        "case": label,
        "ret": str(ret),
        "secs": f"{secs:.3f}",
        "mbps": f"{thr:.3f}",
        "ok": "1" if ret != 0 else "0",
        "log": log.name,
    }


def case_two_clients(
    server: str,
    port: int,
    drop_seq: List[int],
    drop_rate: float,
) -> Dict[str, str]:
    """caso com 2 clientes em paralelo, parâmetros iguais"""
    label = "two_clients"
    out1 = DOWNLOADS / "client1_file.bin"
    out2 = DOWNLOADS / "client2_file.bin"

    cmd1 = [
        PY,
        str(CLIENT),
        "--server",
        server,
        "--port",
        str(port),
        "--path",
        "/test_12mb.bin",
        "--out",
        str(out1),
    ]
    cmd2 = [
        PY,
        str(CLIENT),
        "--server",
        server,
        "--port",
        str(port),
        "--path",
        "/test_40mb.bin",
        "--out",
        str(out2),
    ]

    if drop_seq:
        cmd1 += ["--drop", ",".join(str(x) for x in drop_seq)]
        cmd2 += ["--drop", ",".join(str(x) for x in drop_seq)]
    if drop_rate > 0:
        cmd1 += ["--drop-rate", str(drop_rate)]
        cmd2 += ["--drop-rate", str(drop_rate)]

    log1 = LOGDIR / f"client_{label}_1.log"
    log2 = LOGDIR / f"client_{label}_2.log"
    t0 = time.perf_counter()
    p1 = sp.Popen(
        cmd1, cwd=str(BASE), stdout=open(log1, "w", encoding="utf-8"), stderr=sp.STDOUT
    )
    p2 = sp.Popen(
        cmd2, cwd=str(BASE), stdout=open(log2, "w", encoding="utf-8"), stderr=sp.STDOUT
    )
    r1 = p1.wait()
    r2 = p2.wait()
    t1 = time.perf_counter()

    ok = 0
    if r1 == 0 and r2 == 0 and out1.exists() and out2.exists():
        if sha256_path(SHARED / "test_12mb.bin") == sha256_path(out1) and sha256_path(
            SHARED / "test_12mb.bin"
        ) == sha256_path(out2):
            ok = 1

    secs = t1 - t0
    total_mb = 2 * (SHARED / "test_12mb.bin").stat().st_size / (1024 * 1024)
    thr = total_mb / secs if secs > 0 else 0.0
    return {
        "case": label,
        "ret": str(max(r1, r2)),
        "secs": f"{secs:.3f}",
        "mbps": f"{thr:.3f}",
        "ok": str(ok),
        "log": f"{log1.name},{log2.name}",
    }


def case_interrupt(
    server_proc: sp.Popen,
    server: str,
    port: int,
    drop_seq: List[int],
    drop_rate: float,
) -> Dict[str, str]:
    """caso com queda do servidor no meio da transferência (espera falha)"""
    label = "interrupt"
    out = DOWNLOADS / "interrupt.bin"
    cmd = [
        PY,
        str(CLIENT),
        "--server",
        server,
        "--port",
        str(port),
        "--path",
        "/test_12mb.bin",
        "--out",
        str(out),
    ]
    # força perdas neste caso
    cmd += ["--drop", "1,2,3,5,8,13,21"]
    cmd += ["--drop-rate", "0.01"]

    log = LOGDIR / f"client_{label}.log"
    p = sp.Popen(
        cmd, cwd=str(BASE), stdout=open(log, "w", encoding="utf-8"), stderr=sp.STDOUT
    )
    time.sleep(1.5)  # pequena janela antes de derrubar
    stop_server(server_proc)
    rc = p.wait()
    return {
        "case": label,
        "ret": str(rc),
        "secs": "-",
        "mbps": "-",
        "ok": "1" if rc != 0 else "0",
        "log": log.name,
    }


# ---------------------- main ----------------------
def main():
    """tb: orquestra servidor, roda casos e resume resultados"""
    ap = argparse.ArgumentParser(description="TB para o projeto UDP-File (UF)")
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument(
        "--size-mb", type=int, default=12, help="tamanho do arquivo principal (mb)"
    )
    ap.add_argument(
        "--cases", default="normal", help="casos: normal,missing,two_clients,interrupt"
    )
    ap.add_argument(
        "--drop", default="", help="lista de seqs para descartar, ex.: 3,7,11"
    )
    ap.add_argument(
        "--drop-rate",
        type=float,
        default=0.0,
        help="probabilidade de descartar um data no cliente",
    )
    ap.add_argument(
        "--pace-every", type=int, default=50, help="pausa a cada n pacotes no servidor"
    )
    ap.add_argument(
        "--pace-sleep",
        type=float,
        default=0.001,
        help="duração da pausa no servidor (s)",
    )
    ap.add_argument(
        "--keep-server",
        action="store_true",
        help="não encerrar servidor ao final (debug)",
    )
    args = ap.parse_args()

    # checagens básicas
    if not SERVER.exists() or not CLIENT.exists():
        print("[TB] ERRO: server.py/client.py não encontrados ao lado deste script.")
        sys.exit(1)

    ensure_dirs()

    # prepara arquivos de teste
    ensure_test_file(SHARED / "test_12mb.bin", max(12, args.size_mb))
    ensure_test_file(SHARED / "test_40mb.bin", 40)

    print("[TB] SHA-256 origem:")
    print("  test_12mb.bin:", sha256_path(SHARED / "test_12mb.bin"))
    print("  test_40mb.bin:", sha256_path(SHARED / "test_40mb.bin"))

    # limpa downloads antigos
    print("[TB] Limpando downloads antigos...")
    for p in DOWNLOADS.glob("*"):
        try:
            p.unlink()
        except Exception:
            pass

    # limpa logs antigos
    print("[TB] Limpando logs antigos...")
    for p in LOGDIR.glob("*.log"):
        try:
            p.unlink()
        except Exception:
            pass

    # inicia servidor
    srv, srv_log = start_server(args.port, SHARED, args.pace_every, args.pace_sleep)

    results: List[Dict[str, str]] = []
    try:
        drop_seq = parse_list_ints(args.drop)
        for case in parse_list_str(args.cases):
            case = case.lower()
            if case == "normal":
                results.append(
                    case_normal(
                        args.server,
                        args.port,
                        "/test_12mb.bin",
                        "test_normal.bin",
                        drop_seq,
                        args.drop_rate,
                    )
                )
            elif case == "missing":
                results.append(case_missing(args.server, args.port))
            elif case == "two_clients":
                results.append(
                    case_two_clients(args.server, args.port, drop_seq, args.drop_rate)
                )
            elif case == "interrupt":
                # para interrupt, aumenta pace_sleep e reinicia servidor
                stop_server(srv)
                time.sleep(0.5)
                srv, srv_log = start_server(
                    args.port, SHARED, args.pace_every, max(0.005, args.pace_sleep * 5)
                )
                results.append(
                    case_interrupt(
                        srv, args.server, args.port, drop_seq, args.drop_rate
                    )
                )
                # religar servidor se houver mais casos
                if case != parse_list_str(args.cases)[-1]:
                    srv, srv_log = start_server(
                        args.port, SHARED, args.pace_every, args.pace_sleep
                    )
            else:
                print(f"[TB] Caso desconhecido: {case}")

        for r in results:
            status = "OK" if r.get("ok") == "1" else "FALHA"
            print(
                f"  - {r['case']:<22} {status}  tempo={r['secs']}s  thr={r['mbps']} MB/s  log={r['log']}"
            )

    finally:
        if not args.keep_server:
            stop_server(srv)
        print(f"[TB] Log do servidor: {srv_log}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[TB] Interrompido pelo usuário")
