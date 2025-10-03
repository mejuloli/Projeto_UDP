from __future__ import annotations

import argparse
import os
import socket
import struct
import threading
import time
import traceback
from pathlib import Path
from typing import Dict, Tuple, Optional, Set, List

from wire import (
    MsgType,
    ProtocolError,
    DEFAULT_CHUNK_SIZE,
    make_datagram,
    parse_datagram,
    build_meta,
    build_err,
    parse_nack,
    sha256_path,
    Header,
)

# parâmetros de operação e pacing
CHUNK_SIZE = DEFAULT_CHUNK_SIZE  # bytes por bloco data
ACK_WAIT_S = 1.0  # espera curta por ack(meta)
ROUND_WAIT_S = 2.0  # espera por nack/ok após eot
MAX_TOTAL_ROUNDS = 100  # limite total de rounds
MAX_UNPRODUCTIVE_ROUNDS = 8  # rounds improdutivos seguidos
MIN_PROGRESS_RATIO = 0.05  # 5% de progresso mínimo
PACE_EVERY = 50  # pausa a cada n pacotes
PACE_SLEEP_S = 0.001  # duração da pausa
SOCKET_TIMEOUT_S = 0.2  # timeout do recv do servidor


# -------- helpers --------
def safe_join(base: Path, user_path: str) -> Optional[Path]:
    """garante que o caminho solicitado fique dentro de base (evita path traversal)"""
    candidate = (base / user_path.lstrip("/\\")).resolve()
    try:
        base_resolved = base.resolve(strict=True)
    except FileNotFoundError:
        base_resolved = base.resolve()
    if base_resolved in candidate.parents or candidate == base_resolved:
        return candidate
    return None


def gen_file_id() -> int:
    """gera identificador uint32 pseudo-aleatório para a sessão"""
    return struct.unpack("!I", os.urandom(4))[0]


class Session(threading.Thread):
    """sessão de envio para um cliente/arquivo"""

    # responsabilidades:
    # - validar caminho e abrir arquivo
    # - calcular metadados (tamanho, total, sha-256)
    # - enviar meta e (opcionalmente) aguardar ack(meta)
    # - enviar jato inicial de data (seq 0..total-1)
    # - enviar eot e processar nack/ok em rounds
    # - finalizar ao receber ok ou ao atingir limites

    def __init__(
        self,
        sock: socket.socket,
        client_addr: Tuple[str, int],
        base_dir: Path,
        rel_path: str,
    ):
        super().__init__(daemon=True)
        self.sock = sock
        self.client_addr = client_addr
        self.base_dir = base_dir
        self.rel_path = rel_path

        self.file_path: Optional[Path] = None
        self.file_size: int = 0
        self.total: int = 0
        self.sha256: bytes = b"\x00" * 32
        self.file_id: int = gen_file_id()

        self._stop = threading.Event()
        self._round_cond = threading.Condition()
        self._incoming_msgs: List[Tuple[MsgType, Header, bytes]] = []  # fila de entrada

    # --- api do loop principal ---
    def enqueue_msg(self, mtype: MsgType, hdr: Header, payload: bytes) -> None:
        """enfileira mensagem recebida para esta sessão"""
        with self._round_cond:
            self._incoming_msgs.append((mtype, hdr, payload))
            self._round_cond.notify_all()

    def stop(self):
        """pede para encerrar a sessão"""
        self._stop.set()
        with self._round_cond:
            self._round_cond.notify_all()

    # --- execução da thread ---
    def run(self):
        """ponto de entrada da thread; garante limpeza da sessão"""
        try:
            self._run_session()
        except Exception as e:
            print(f"[SESSION] erro inesperado: {e}")
            print(traceback.format_exc())
        finally:
            try:
                SESSIONS.pop((self.client_addr, self.file_id), None)
            except Exception:
                pass

    def _run_session(self):
        """fluxo principal da sessão (meta -> data -> eot/nack -> ok)"""
        target = safe_join(self.base_dir, self.rel_path)
        if not target or not target.exists() or not target.is_file():
            print(
                f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] arquivo não encontrado: {self.rel_path}"
            )
            self._send_err(1, "Arquivo não encontrado")
            return
        self.file_path = target

        # metadados do arquivo
        self.file_size = self.file_path.stat().st_size
        self.total = (
            (self.file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if self.file_size > 0 else 1
        )
        self.sha256 = sha256_path(str(self.file_path))

        print(
            f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] nova sessão | "
            f"arquivo={self.file_path.name} size={self.file_size}B total={self.total} blocos"
        )

        # envia meta
        meta_payload = build_meta(
            file_size=self.file_size,
            chunk_size=CHUNK_SIZE,
            total=self.total,
            sha256=self.sha256,
            file_name=self.file_path.name,
        )
        self._send(MsgType.META, payload=meta_payload)
        self._wait_optional_ack(what=1, timeout=ACK_WAIT_S)

        # envia jato inicial de data
        self._send_all_data_once()

        # rounds de retransmissão dirigidos por nack
        total_rounds = 0
        unproductive_rounds = 0
        last_nack_set: Set[int] = set()
        current_nack_set: Set[int] = set()

        while not self._stop.is_set():
            # informa fim de rodada
            self._send(MsgType.EOT)
            # espera nack ou ok
            mtype, hdr, payload = self._wait_for(
                {MsgType.NACK, MsgType.OK}, timeout=ROUND_WAIT_S
            )
            total_rounds += 1

            if mtype is None:
                # sem resposta; conta como improdutivo
                unproductive_rounds += 1
                print(
                    f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] timeout aguardando resposta "
                    f"(round {total_rounds}, improdutivos: {unproductive_rounds})"
                )
                if total_rounds > MAX_TOTAL_ROUNDS:
                    print(
                        f"[SERVER][sess {self.file_id}@...] limite total de rounds atingido ({MAX_TOTAL_ROUNDS})"
                    )
                    break
                if unproductive_rounds > MAX_UNPRODUCTIVE_ROUNDS:
                    print(
                        f"[SERVER][sess {self.file_id}@...] muitos rounds improdutivos ({unproductive_rounds})"
                    )
                    break
                continue

            if mtype == MsgType.OK:
                print(
                    f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] OK recebido; transferência concluída "
                    f"(rounds: {total_rounds})"
                )
                break

            if mtype == MsgType.NACK:
                seqs = parse_nack(payload)
                if not seqs:
                    unproductive_rounds += 1
                    continue

                current_nack_set = set(s for s in seqs if 0 <= s < self.total)

                if last_nack_set:
                    threshold = max(1, int(len(last_nack_set) * MIN_PROGRESS_RATIO))
                    progress_made = len(last_nack_set) - len(
                        last_nack_set.intersection(current_nack_set)
                    )
                    if progress_made >= threshold:
                        unproductive_rounds = 0
                        print(
                            f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] rodada produtiva: "
                            f"{progress_made} blocos resolvidos (threshold: {threshold}), round {total_rounds}"
                        )
                    else:
                        unproductive_rounds += 1
                        print(
                            f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] rodada improdutiva: "
                            f"{progress_made} < {threshold}, round {total_rounds} (improdutivos: {unproductive_rounds})"
                        )
                else:
                    unproductive_rounds = 0

                last_nack_set = current_nack_set.copy()
                self._retransmit(current_nack_set)

                if total_rounds > MAX_TOTAL_ROUNDS:
                    print(
                        f"[SERVER][sess {self.file_id}@...] limite total de rounds atingido ({MAX_TOTAL_ROUNDS})"
                    )
                    break
                if unproductive_rounds > MAX_UNPRODUCTIVE_ROUNDS:
                    print(
                        f"[SERVER][sess {self.file_id}@...] muitos rounds improdutivos consecutivos ({unproductive_rounds})"
                    )
                    break

        print(
            f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] sessão encerrada"
        )

    # --- envio de blocos ---
    def _send_all_data_once(self):
        """envia jato inicial de data sequencial (aplica pacing)"""
        assert self.file_path is not None
        sent = 0
        with open(self.file_path, "rb") as f:
            for seq in range(self.total):
                data = f.read(CHUNK_SIZE)
                if not data and self.file_size == 0:
                    data = b""  # arquivo vazio → 1 bloco
                self._send(MsgType.DATA, seq=seq, total=self.total, payload=data)
                sent += 1
                if sent % PACE_EVERY == 0:
                    time.sleep(PACE_SLEEP_S)
        print(
            f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] primeiro jato completo: {sent} blocos enviados"
        )

    def _retransmit(self, seqs: Set[int]):
        """retransmite data para seqs solicitadas em nack"""
        assert self.file_path is not None
        count = 0
        with open(self.file_path, "rb") as f:
            for seq in sorted(seqs):
                f.seek(seq * CHUNK_SIZE)
                data = f.read(CHUNK_SIZE)
                self._send(MsgType.DATA, seq=seq, total=self.total, payload=data)
                count += 1
                if count % PACE_EVERY == 0:
                    time.sleep(PACE_SLEEP_S)
        if count > 0:
            sample = sorted(list(seqs))[:10]
            print(
                f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] nack recebido; retransmitindo {count} blocos: "
                f"{sample}{'...' if len(seqs) > 10 else ''}"
            )

    # --- utilitários de envio/espera ---
    def _send(
        self, msg_type: MsgType, *, seq: int = 0, total: int = 0, payload: bytes = b""
    ):
        """empacota e envia datagrama para o cliente desta sessão"""
        dgram = make_datagram(
            msg_type, file_id=self.file_id, seq=seq, total=total, payload=payload
        )
        try:
            self.sock.sendto(dgram, self.client_addr)
        except ConnectionResetError:
            print(
                f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] cliente desconectou"
            )
            self._stop.set()
        except OSError as e:
            print(
                f"[SERVER][sess {self.file_id}@{self.client_addr[0]}:{self.client_addr[1]}] erro ao enviar: {e}"
            )

    def _send_err(self, code: int, msg: str):
        """envia err com code:uint16 e mensagem utf-8 (file_id=0)"""
        payload = build_err(code, msg)
        dgram = make_datagram(MsgType.ERR, file_id=0, seq=0, total=0, payload=payload)
        try:
            self.sock.sendto(dgram, self.client_addr)
        except (ConnectionResetError, OSError) as e:
            print(f"[SERVER] erro ao enviar ERR para {self.client_addr}: {e}")

    def _wait_optional_ack(self, *, what: int, timeout: float) -> None:
        """aguarda ack específico por curto período (não bloqueante)"""
        deadline = time.time() + timeout
        while time.time() < deadline and not self._stop.is_set():
            mtype, hdr, payload = self._wait_for(
                {MsgType.ACK}, timeout=deadline - time.time()
            )
            if mtype is None:
                return
            if hdr is None:
                continue
            if hdr.file_id != self.file_id:
                continue
            if payload and payload[0] == what:
                return

    def _wait_for(
        self, types: Set[MsgType], *, timeout: float
    ) -> Tuple[Optional[MsgType], Optional[Header], bytes]:
        """espera mensagem da fila desta sessão (filtro por tipos)"""
        end = time.time() + max(0.0, timeout)
        with self._round_cond:
            while not self._stop.is_set():
                for i, (t, h, p) in enumerate(self._incoming_msgs):
                    if t in types and (h.file_id == self.file_id or t == MsgType.ACK):
                        self._incoming_msgs.pop(i)
                        return t, h, p
                remaining = end - time.time()
                if remaining <= 0:
                    return None, None, b""
                self._round_cond.wait(timeout=remaining)
        return None, None, b""


# -------- loop principal do servidor --------
SESSIONS: Dict[Tuple[Tuple[str, int], int], Session] = {}


def server_loop(host: str, port: int, shared_dir: Path):
    """loop principal: bind -> recebe -> roteia para sessões"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(SOCKET_TIMEOUT_S)

    print(f"[SERVER] Escutando REQ em {host}:{port}")
    print(f"[SERVER] Compartilhando diretório: {shared_dir.resolve()}")

    while True:
        try:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
            except OSError as e:
                print(f"[SERVER] erro de socket: {e}")
                continue

            try:
                hdr, payload = parse_datagram(data)
            except ProtocolError as e:
                print(f"[SERVER] datagrama inválido de {addr}: {e}")
                continue

            if hdr.type == MsgType.GET:
                # inicia nova sessão para o pedido
                rel_path = payload.decode("utf-8", errors="strict")
                sess = Session(sock, addr, shared_dir, rel_path)
                key = (addr, sess.file_id)
                SESSIONS[key] = sess
                sess.start()
                continue

            # roteia para sessão existente pelo par (addr, file_id)
            routed = False
            for (addr_key, fid), sess in list(SESSIONS.items()):
                if addr_key == addr and fid == hdr.file_id:
                    sess.enqueue_msg(hdr.type, hdr, payload)
                    routed = True
                    break
            if not routed:
                # possivelmente ack cedo; ignorar
                pass

        except KeyboardInterrupt:
            print("\n[SERVER] encerrando por KeyboardInterrupt")
            break
        except Exception:
            print("[SERVER] erro no loop principal:\n" + traceback.format_exc())
            continue

    # encerra sessões ativas
    for sess in list(SESSIONS.values()):
        sess.stop()
    for sess in list(SESSIONS.values()):
        sess.join(timeout=1)


# -------- cli --------
def parse_args() -> argparse.Namespace:
    """lê argumentos do servidor"""
    p = argparse.ArgumentParser(description="Servidor UDP-File (UF)")
    p.add_argument(
        "--host", default="0.0.0.0", help="endereço para bind (default: 0.0.0.0)"
    )
    p.add_argument("--port", type=int, default=9000, help="porta udp (>1024)")
    p.add_argument(
        "--shared", type=str, default="./shared", help="diretório base de arquivos"
    )
    p.add_argument(
        "--pace-every",
        type=int,
        default=PACE_EVERY,
        help=f"número de pacotes antes de fazer pausa (default: {PACE_EVERY})",
    )
    p.add_argument(
        "--pace-sleep",
        type=float,
        default=PACE_SLEEP_S,
        help=f"duração da pausa em segundos (default: {PACE_SLEEP_S})",
    )
    return p.parse_args()


def main():
    """entrada principal: valida, prepara e inicia o servidor"""
    args = parse_args()
    if args.port <= 1024:
        print("[SERVER] ERRO: porta deve ser > 1024")
        return
    if args.pace_every <= 0:
        print("[SERVER] ERRO: --pace-every deve ser > 0")
        return
    if args.pace_sleep < 0:
        print("[SERVER] ERRO: --pace-sleep deve ser >= 0")
        return

    # aplica pacing global
    global PACE_EVERY, PACE_SLEEP_S
    PACE_EVERY = args.pace_every
    PACE_SLEEP_S = args.pace_sleep

    shared_dir = Path(args.shared)
    shared_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"[SERVER] Configuração de pacing: a cada {PACE_EVERY} pacotes, pausa {PACE_SLEEP_S}s"
    )
    server_loop(args.host, args.port, shared_dir)


if __name__ == "__main__":
    main()
