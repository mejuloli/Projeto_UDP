from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct
import zlib
import hashlib
from typing import Iterable, List, Tuple

# constantes do protocolo
MAGIC = b"UF"  # identificador do protocolo
VERSION = 1  # versão do header

# formato do header: magic, ver, type, file_id, seq, total, payload_len, crc32
HEADER_FMT = "!2sBBIIIHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# parâmetros fixos do protocolo
DEFAULT_CHUNK_SIZE = 1200  # tamanho padrão de chunk em DATA
MAX_FILENAME_LEN = 4096  # limite do nome do arquivo em META
MAX_NACK_IN_ONE_MSG = 500  # limite de seqs em um NACK


# exceção para erros no protocolo
class ProtocolError(Exception):
    """erro em serialização ou validação do protocolo"""


# tipos de mensagem
class MsgType(IntEnum):
    GET = 0x01
    ERR = 0x02
    META = 0x03
    DATA = 0x04
    EOT = 0x05
    NACK = 0x06
    OK = 0x07
    ACK = 0x08


# representação do header
@dataclass(frozen=True)
class Header:
    """estrutura imutável do header de um datagrama"""

    magic: bytes
    ver: int
    type: MsgType
    file_id: int
    seq: int
    total: int
    payload_len: int
    crc32: int

    def pack(self) -> bytes:
        """serializa o header em bytes"""
        return struct.pack(
            HEADER_FMT,
            self.magic,
            self.ver,
            int(self.type),
            self.file_id & 0xFFFFFFFF,
            self.seq & 0xFFFFFFFF,
            self.total & 0xFFFFFFFF,
            self.payload_len & 0xFFFF,
            self.crc32 & 0xFFFFFFFF,
        )

    @staticmethod
    def make(
        msg_type: MsgType,
        *,
        file_id: int = 0,
        seq: int = 0,
        total: int = 0,
        payload: bytes = b"",
    ) -> "Header":
        """cria um header válido a partir dos parâmetros"""
        if not isinstance(msg_type, MsgType):
            raise ProtocolError("msg_type inválido")
        if len(payload) > 0xFFFF:
            raise ProtocolError("payload_len excede 65535")
        crc = crc32_bytes(payload) if payload else 0
        return Header(MAGIC, VERSION, msg_type, file_id, seq, total, len(payload), crc)


# funções de header
def pack_header(h: Header) -> bytes:
    """serializa header em bytes"""
    return h.pack()


def unpack_header(data: bytes) -> Tuple[Header, bytes]:
    """desempacota datagrama em (header, payload)"""
    if len(data) < HEADER_SIZE:
        raise ProtocolError(f"datagrama curto: {len(data)} < {HEADER_SIZE}")
    fields = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    magic, ver, mtype, file_id, seq, total, payload_len, crc32 = fields

    if magic != MAGIC:
        raise ProtocolError("magic inválido")
    if ver != VERSION:
        raise ProtocolError(f"versão não suportada: {ver}")

    try:
        mtype_enum = MsgType(mtype)
    except ValueError as e:
        raise ProtocolError(f"tipo de mensagem desconhecido: {mtype}") from e

    if len(data) != HEADER_SIZE + payload_len:
        raise ProtocolError("comprimento total não confere")

    payload = data[HEADER_SIZE:]
    if payload_len:
        calc = crc32_bytes(payload)
        if calc != crc32:
            raise ProtocolError("crc32 não confere")

    hdr = Header(magic, ver, mtype_enum, file_id, seq, total, payload_len, crc32)
    return hdr, payload


# funções de integridade
def crc32_bytes(b: bytes) -> int:
    """calcula crc32 de bytes"""
    return zlib.crc32(b) & 0xFFFFFFFF


def sha256_bytes(b: bytes) -> bytes:
    """calcula sha256 de bytes"""
    return hashlib.sha256(b).digest()


def sha256_path(path: str, *, bufsize: int = 1024 * 1024) -> bytes:
    """calcula sha256 de um arquivo"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(bufsize)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


# payload GET
def build_get(path: str) -> bytes:
    """constrói payload GET"""
    data = path.encode("utf-8")
    if len(data) > 0xFFFF:
        raise ProtocolError("GET path muito longo")
    return data


def parse_get(payload: bytes) -> str:
    """decodifica payload GET"""
    return payload.decode("utf-8", errors="strict")


# payload ERR
def build_err(code: int, msg: str) -> bytes:
    """constrói payload ERR"""
    if not (0 <= code <= 0xFFFF):
        raise ProtocolError("ERR code inválido")
    msg_b = msg.encode("utf-8")
    return struct.pack("!H", code) + msg_b


def parse_err(payload: bytes) -> Tuple[int, str]:
    """parseia payload ERR"""
    if len(payload) < 2:
        raise ProtocolError("payload ERR curto")
    (code,) = struct.unpack("!H", payload[:2])
    msg = payload[2:].decode("utf-8", errors="replace")
    return code, msg


# payload META
def build_meta(
    *, file_size: int, chunk_size: int, total: int, sha256: bytes, file_name: str
) -> bytes:
    """constrói payload META"""
    if not (0 <= file_size < 1 << 64):
        raise ProtocolError("file_size inválido")
    if not (0 < chunk_size <= 0xFFFF):
        raise ProtocolError("chunk_size inválido")
    if not (0 <= total < 1 << 32):
        raise ProtocolError("total inválido")
    if len(sha256) != 32:
        raise ProtocolError("sha256 inválido")
    name_b = file_name.encode("utf-8")
    if len(name_b) > MAX_FILENAME_LEN:
        raise ProtocolError("nome de arquivo muito longo")
    return (
        struct.pack("!QHI32sH", file_size, chunk_size, total, sha256, len(name_b))
        + name_b
    )


def parse_meta(payload: bytes) -> Tuple[int, int, int, bytes, str]:
    """parseia payload META"""
    header_len = struct.calcsize("!QHI32sH")
    if len(payload) < header_len:
        raise ProtocolError("payload META curto")
    file_size, chunk_size, total, sha256, name_len = struct.unpack(
        "!QHI32sH", payload[:header_len]
    )
    name_b = payload[header_len:]
    if len(name_b) != name_len:
        raise ProtocolError("name_len inválido")
    file_name = name_b.decode("utf-8")
    return file_size, chunk_size, total, sha256, file_name


# payload NACK
def build_nack(seqs: Iterable[int]) -> bytes:
    """constrói payload NACK"""
    seq_list = list(seqs)
    if len(seq_list) > 0xFFFF:
        raise ProtocolError("NACK muito grande")
    count = len(seq_list)
    buf = [struct.pack("!H", count)]
    for s in seq_list:
        if not (0 <= s < 1 << 32):
            raise ProtocolError("seq inválida em NACK")
        buf.append(struct.pack("!I", s))
    return b"".join(buf)


def parse_nack(payload: bytes) -> List[int]:
    """parseia payload NACK"""
    if len(payload) < 2:
        raise ProtocolError("payload NACK curto")
    (count,) = struct.unpack("!H", payload[:2])
    expected = 2 + 4 * count
    if len(payload) != expected:
        raise ProtocolError("comprimento inválido em NACK")
    seqs = []
    off = 2
    for _ in range(count):
        (s,) = struct.unpack("!I", payload[off : off + 4])
        off += 4
        seqs.append(s)
    return seqs


# payload ACK
def build_ack(what: int) -> bytes:
    """constrói payload ACK"""
    if what not in (1, 2):
        raise ProtocolError("ACK inválido")
    return struct.pack("!B", what)


def parse_ack(payload: bytes) -> int:
    """parseia payload ACK"""
    if len(payload) != 1:
        raise ProtocolError("payload ACK inválido")
    (what,) = struct.unpack("!B", payload)
    if what not in (1, 2):
        raise ProtocolError("ACK.what inválido")
    return what


# montagem de datagrama
def make_datagram(
    msg_type: MsgType,
    *,
    file_id: int = 0,
    seq: int = 0,
    total: int = 0,
    payload: bytes = b"",
) -> bytes:
    """monta datagrama completo (header + payload)"""
    h = Header.make(msg_type, file_id=file_id, seq=seq, total=total, payload=payload)
    return h.pack() + payload


def parse_datagram(dgram: bytes) -> Tuple[Header, bytes]:
    """desempacota datagrama"""
    return unpack_header(dgram)


# validação do payload DATA
def validate_data_payload(
    payload: bytes, *, max_chunk: int = DEFAULT_CHUNK_SIZE
) -> None:
    """valida payload DATA"""
    if len(payload) == 0:
        raise ProtocolError("payload DATA vazio")
    if len(payload) > max_chunk:
        raise ProtocolError("payload DATA muito grande")


__all__ = [
    "MAGIC",
    "VERSION",
    "HEADER_FMT",
    "HEADER_SIZE",
    "DEFAULT_CHUNK_SIZE",
    "MAX_FILENAME_LEN",
    "MAX_NACK_IN_ONE_MSG",
    "ProtocolError",
    "MsgType",
    "Header",
    "pack_header",
    "unpack_header",
    "crc32_bytes",
    "sha256_bytes",
    "sha256_path",
    "build_get",
    "parse_get",
    "build_err",
    "parse_err",
    "build_meta",
    "parse_meta",
    "build_nack",
    "parse_nack",
    "build_ack",
    "parse_ack",
    "make_datagram",
    "parse_datagram",
    "validate_data_payload",
]
