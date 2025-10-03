from __future__ import annotations

import argparse
import os
import random
import socket
import sys
from pathlib import Path
from typing import Optional, Set

from wire import (
    MsgType,
    ProtocolError,
    DEFAULT_CHUNK_SIZE,
    MAX_NACK_IN_ONE_MSG,
    make_datagram,
    parse_datagram,
    build_get,
    build_nack,
    parse_meta,
)

# tempo de espera do recv em segundos
RECV_TIMEOUT_S = 3.0
# limite total de rodadas de retransmissão
MAX_TOTAL_ROUNDS = 35
# limite de rodadas seguidas sem progresso
MAX_UNPRODUCTIVE_ROUNDS = 8
# fração mínima de progresso por rodada
MIN_PROGRESS_RATIO = 0.05


class Client:
    """cliente que baixa arquivo via protocolo uf sobre udp"""

    # visão geral do estado:
    # - server: (ip, porta) do servidor udp
    # - req_path: caminho requisitado no servidor
    # - out_path: caminho local de saída (ou None para usar o nome do META)
    # - drop_once: seqs para descartar uma vez (simulação)
    # - drop_rate: probabilidade de descartar DATA aleatoriamente
    # - sock: socket udp com timeout
    #
    # sessão (preenchida com META):
    # - file_id, total, chunk_size, file_size, sha256, file_name
    #
    # recepção:
    # - received: seqs gravadas
    # - missing: seqs faltantes (recalculado por rodada)
    # - tmp_path/tmp_file: arquivo temporário ".part"

    def __init__(
        self,
        server_ip: str,
        server_port: int,
        req_path: str,
        out_path: Optional[Path],
        drop_once: Set[int],
        drop_rate: float,
    ):
        # destino do servidor
        self.server = (server_ip, server_port)
        # caminho no servidor
        self.req_path = req_path
        # saída local
        self.out_path = out_path
        # simulação: descartar seqs específicas uma vez
        self.drop_once = set(drop_once)
        # simulação: probabilidade de descarte aleatório
        self.drop_rate = drop_rate

        # socket udp com timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(RECV_TIMEOUT_S)

        # metadados da sessão
        self.file_id: Optional[int] = None
        self.total: int = 0
        self.chunk_size: int = DEFAULT_CHUNK_SIZE
        self.file_size: int = 0
        self.sha256: bytes = b"\x00" * 32
        self.file_name: str = "download.bin"

        # controle de recepção
        self.received = set()
        self.missing = set()
        self.tmp_path: Optional[Path] = None
        self.tmp_file = None

    # ---------- api principal ----------
    def run(self):
        """fluxo principal: get -> meta/ack -> data/eot -> nack/retry -> validação/ok"""
        # 1) envia GET
        self._send_get()
        # 2) espera META
        print("[CLIENT] Aguardando META do servidor...")
        hdr, payload = self._recv_expect(MsgType.META)
        self._handle_meta(hdr, payload)
        # 3) envia ACK(META)
        self._send_ack(what=1)
        # 4) recebe DATA até EOT (primeiro jato)
        print("[CLIENT] Recebendo primeiro jato de dados...")
        self._recv_until_eot()
        # 5) laço de NACK até completar
        total_rounds = 0
        unproductive_rounds = 0
        last_received_count = len(self.received)
        while True:
            self.missing = set(range(self.total)) - self.received
            if not self.missing:
                self._send_ack(what=2)
                ok = self._finish_and_validate()
                if ok:
                    self._send_ok()
                    print(
                        f"[CLIENT] OK: arquivo salvo em {self.out_path}, SHA256 confere"
                    )
                break
            else:
                if total_rounds >= MAX_TOTAL_ROUNDS:
                    print(
                        f"[CLIENT] ERRO: máximo de rounds NACK atingido ({MAX_TOTAL_ROUNDS})"
                    )
                    print(
                        f"[CLIENT] Recebidos {len(self.received)}/{self.total} blocos "
                        f"({(len(self.received) / self.total * 100):.1f}%)"
                    )
                    raise SystemExit(1)
                if unproductive_rounds >= MAX_UNPRODUCTIVE_ROUNDS:
                    print(
                        f"[CLIENT] ERRO: muitos rounds improdutivos ({MAX_UNPRODUCTIVE_ROUNDS}); "
                        "servidor possivelmente parou"
                    )
                    print(
                        f"[CLIENT] Recebidos {len(self.received)}/{self.total} blocos "
                        f"({(len(self.received) / self.total * 100):.1f}%)"
                    )
                    raise SystemExit(1)

                missing_sample = sorted(list(self.missing))[:10]
                missing_str = str(missing_sample)[1:-1]
                if len(self.missing) > 10:
                    missing_str += ", ..."
                print(
                    f"[CLIENT] NACK enviado: {len(self.missing)} faltantes "
                    f"[{missing_str}] (round {total_rounds + 1}, improdutivos: {unproductive_rounds})"
                )
                packets_sent = self._send_nacks(self.missing)

            # recebe retransmissões até novo EOT
            self._recv_until_eot(packets_sent)

            # mede progresso da rodada
            current_received_count = len(self.received)
            progress_this_round = current_received_count - last_received_count

            # limite mínimo de progresso: máx(1, 5% dos faltantes)
            missing_before_round = len(self.missing) + progress_this_round
            min_progress_needed = max(1, int(missing_before_round * MIN_PROGRESS_RATIO))

            if progress_this_round >= min_progress_needed:
                unproductive_rounds = 0
                print(
                    f"[CLIENT] Rodada produtiva: +{progress_this_round} blocos "
                    f"(>= {min_progress_needed})"
                )
                print(
                    f"[CLIENT] Total: {current_received_count}/{self.total} "
                    f"({(current_received_count / self.total * 100):.1f}%)"
                )
            else:
                unproductive_rounds += 1
                if progress_this_round > 0:
                    print(
                        f"[CLIENT] Rodada improdutiva: +{progress_this_round} blocos "
                        f"(< {min_progress_needed})"
                    )
                else:
                    print("[CLIENT] Nenhum progresso nesta rodada")
                print(
                    f"[CLIENT] Rounds improdutivos consecutivos: "
                    f"{unproductive_rounds}/{MAX_UNPRODUCTIVE_ROUNDS}"
                )

            last_received_count = current_received_count
            total_rounds += 1

    # ---------- envio ----------
    def _send_get(self):
        """envia GET com path utf-8"""
        payload = build_get(self.req_path)
        dgram = make_datagram(MsgType.GET, payload=payload)
        try:
            self.sock.sendto(dgram, self.server)
            print(f"[CLIENT] REQ enviado: {self.req_path} -> {self.server}")
        except (ConnectionResetError, OSError) as e:
            raise SystemExit(f"[CLIENT] erro ao enviar GET: {e}")

    def _send_ack(self, what: int):
        """envia ACK de META (1) ou EOT (2)"""
        from wire import build_ack  # evita import circular

        payload = build_ack(what)
        dgram = make_datagram(MsgType.ACK, file_id=self.file_id or 0, payload=payload)
        try:
            self.sock.sendto(dgram, self.server)
        except (ConnectionResetError, OSError) as e:
            print(f"[CLIENT] erro ao enviar ACK: {e}")

    def _send_ok(self):
        """envia OK final sem payload"""
        dgram = make_datagram(MsgType.OK, file_id=self.file_id or 0)
        try:
            self.sock.sendto(dgram, self.server)
        except (ConnectionResetError, OSError) as e:
            print(f"[CLIENT] erro ao enviar OK: {e}")

    def _send_nacks(self, seqs: Set[int]) -> int:
        """envia NACK(s) para solicitar seqs faltantes"""
        packets_sent = 0
        seq_list = sorted(seqs)
        while seq_list:
            chunk = seq_list[:MAX_NACK_IN_ONE_MSG]
            seq_list = seq_list[MAX_NACK_IN_ONE_MSG:]
            payload = build_nack(chunk)
            dgram = make_datagram(
                MsgType.NACK, file_id=self.file_id or 0, payload=payload
            )
            try:
                self.sock.sendto(dgram, self.server)
                packets_sent += 1
            except (ConnectionResetError, OSError) as e:
                print(f"[CLIENT] erro ao enviar NACK: {e}")
        return packets_sent

    # ---------- recepção ----------
    def _recv_expect(self, expected_type: MsgType):
        """aguarda um tipo específico; trata ERR e descarta inválidos"""
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                print(
                    f"[CLIENT] timeout aguardando {expected_type.name} do servidor {self.server}"
                )
                raise SystemExit(1)
            except ConnectionResetError:
                # pode indicar icmp port unreachable no windows; continuar
                continue
            except OSError as e:
                print(f"[CLIENT] erro de socket aguardando {expected_type.name}: {e}")
                continue
            try:
                hdr, payload = parse_datagram(data)
            except ProtocolError as e:
                print(f"[CLIENT] datagrama descartado (erro protocolo): {e}")
                continue
            if addr != self.server:
                continue
            if hdr.type == expected_type:
                return hdr, payload
            if hdr.type == MsgType.ERR:
                self._handle_err(payload)
                raise SystemExit(1)

    def _recv_until_eot(self, qtd_eot: int = 1):
        """recebe DATA contínuo até contar EOT esperado ou timeout"""
        eot_received = 0
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                print("[CLIENT] timeout de recepção; aguardando EOT/novos dados...")
                return
            except ConnectionResetError:
                continue
            except OSError as e:
                print(f"[CLIENT] erro de socket durante recepção: {e}")
                continue
            try:
                hdr, payload = parse_datagram(data)
            except ProtocolError as e:
                print(f"[CLIENT] datagrama descartado (erro protocolo): {e}")
                continue
            if addr != self.server:
                continue

            if hdr.type == MsgType.DATA:
                if self.file_id is not None and hdr.file_id != self.file_id:
                    continue
                self._handle_data(hdr, payload)
            elif hdr.type == MsgType.EOT:
                eot_received += 1
                if eot_received >= qtd_eot:
                    return
            elif hdr.type == MsgType.ERR:
                self._handle_err(payload)
                raise SystemExit(1)

    # ---------- handlers ----------
    def _handle_meta(self, hdr, payload: bytes):
        """processa META: carrega metadados e prepara saída"""
        self.file_id = hdr.file_id
        file_size, chunk_size, total, sha256, file_name = parse_meta(payload)
        self.file_size = file_size
        self.chunk_size = chunk_size
        self.total = total
        self.sha256 = sha256
        self.file_name = file_name

        if self.out_path is None:
            out_name = self.file_name or "download.bin"
            self.out_path = Path(out_name).resolve()
        else:
            self.out_path = Path(self.out_path).resolve()

        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.tmp_path = self.out_path.with_suffix(self.out_path.suffix + ".part")
        self.tmp_file = open(self.tmp_path, "r+b" if self.tmp_path.exists() else "w+b")
        if self.file_size > 0:
            self.tmp_file.truncate(self.file_size)

        self.received = set()

        print(
            f"[CLIENT] META: file_id={self.file_id} size={self.file_size} "
            f"chunk={self.chunk_size} total={self.total} name='{self.file_name}'"
        )

    def _handle_data(self, hdr, payload: bytes):
        """grava DATA válido na posição correta e marca seq recebida"""
        seq = hdr.seq
        if seq >= self.total:
            return
        # simulação de perda por lista
        if seq in self.drop_once:
            self.drop_once.remove(seq)
            print(f"[CLIENT] CORRUPT(sim) seq={seq}")
            return
        # simulação de perda por probabilidade
        if self.drop_rate > 0 and random.random() < self.drop_rate:
            return
        if self.tmp_file is None:
            return
        offset = seq * self.chunk_size
        try:
            self.tmp_file.seek(offset)
            self.tmp_file.write(payload)
            self.received.add(seq)
        except Exception as e:
            print(f"[CLIENT] erro ao gravar seq={seq}: {e}")

    def _handle_err(self, payload: bytes):
        """mostra ERR do servidor (code:uint16 + msg utf-8)"""
        if len(payload) < 2:
            print("[CLIENT] ERRO do servidor (formato desconhecido)")
            return
        code = int.from_bytes(payload[:2], "big")
        msg = payload[2:].decode("utf-8", errors="replace")
        print(f"[CLIENT] ERRO do servidor: code={code} msg={msg}")

    # ---------- finalização ----------
    def _finish_and_validate(self) -> bool:
        """fecha .part, valida sha-256 e move para destino final"""
        if self.tmp_file is None:
            return False
        self.tmp_file.flush()
        os.fsync(self.tmp_file.fileno())
        self.tmp_file.close()
        self.tmp_file = None

        if self.tmp_path is None:
            return False
        from wire import sha256_path

        calc = sha256_path(str(self.tmp_path))
        if calc != self.sha256:
            print("[CLIENT] SHA-256 NÃO confere; arquivo incompleto/corrompido")
            return False
        if self.out_path is None:
            return False
        try:
            if self.out_path.exists():
                self.out_path.unlink()
            os.replace(str(self.tmp_path), str(self.out_path))
        except Exception as e:
            print(f"[CLIENT] falha ao mover arquivo final: {e}")
            return False
        return True


# ---------- cli ----------


def parse_args() -> argparse.Namespace:
    """lê argumentos do cliente"""
    p = argparse.ArgumentParser(description="Cliente UDP-File (UF)")
    p.add_argument("--server", required=True, help="ip do servidor")
    p.add_argument("--port", type=int, default=9000, help="porta do servidor")
    p.add_argument(
        "--path", required=True, help="caminho requisitado (ex.: /arquivo.bin)"
    )
    p.add_argument("--out", default=None, help="caminho de saída local (opcional)")
    p.add_argument(
        "--drop", default="", help="seqs para descartar uma vez, ex.: '1,2,77'"
    )
    p.add_argument(
        "--drop-rate",
        type=float,
        default=0.0,
        help="probabilidade de descartar um DATA (0..1)",
    )
    return p.parse_args()


def main():
    """entrada principal do cliente"""
    args = parse_args()
    if args.port <= 0 or args.port > 65535:
        print("[CLIENT] porta inválida")
        sys.exit(2)
    # parse do --drop
    drop_once = set()
    if args.drop:
        try:
            drop_once = {int(x.strip()) for x in args.drop.split(",") if x.strip()}
        except Exception:
            print("[CLIENT] --drop inválido; use números separados por vírgula")
            sys.exit(2)
    # valida probabilidade
    if not (0.0 <= args.drop_rate <= 1.0):
        print("[CLIENT] --drop-rate deve estar em 0..1")
        sys.exit(2)

    c = Client(
        args.server,
        args.port,
        args.path,
        Path(args.out) if args.out else None,
        drop_once,
        args.drop_rate,
    )
    try:
        c.run()
    except SystemExit as e:
        sys.exit(int(e.code) if isinstance(e.code, int) else 1)
    except KeyboardInterrupt:
        print("\n[CLIENT] interrompido pelo usuário")
        sys.exit(1)


if __name__ == "__main__":
    main()
