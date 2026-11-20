"""
Network Error Detection and LAN Performance Monitoring System
Parity, 8-bit one's-complement checksum, CRC, error injection and retransmission.
Run with: python network_error_detection.py
"""

from time import perf_counter


def text_to_bits(message):
    return "".join(format(byte, "08b") for byte in message.encode("utf-8"))


def parity_frame(data, parity_type="even"):
    if parity_type not in ("even", "odd"):
        raise ValueError("Parity must be 'even' or 'odd'.")
    ones = data.count("1")
    parity_bit = str(ones % 2) if parity_type == "even" else str(1 - ones % 2)
    return data + parity_bit


def parity_check(frame, parity_type="even"):
    if parity_type not in ("even", "odd"):
        raise ValueError("Parity must be 'even' or 'odd'.")
    ones = frame.count("1")
    return ones % 2 == (0 if parity_type == "even" else 1)


def add_ones_complement(a, b):
    total = int(a, 2) + int(b, 2)
    while total > 0xFF:
        total = (total & 0xFF) + (total >> 8)
    return total


def checksum_frame(data):
    padded = data + ("0" * ((8 - len(data) % 8) % 8))
    words = [padded[i:i + 8] for i in range(0, len(padded), 8)]
    total = 0
    for word in words:
        total = add_ones_complement(format(total, "08b"), word)
    checksum = format((~total) & 0xFF, "08b")
    return padded, checksum


def checksum_check(data, checksum):
    if len(checksum) != 8 or any(bit not in "01" for bit in checksum):
        return False
    padded = data + ("0" * ((8 - len(data) % 8) % 8))
    words = [padded[i:i + 8] for i in range(0, len(padded), 8)]
    total = 0
    for word in words:
        total = add_ones_complement(format(total, "08b"), word)
    total = add_ones_complement(format(total, "08b"), checksum)
    return total == 0xFF


def validate_generator(generator):
    if len(generator) < 2:
        raise ValueError("CRC generator must contain at least 2 bits.")
    if generator[0] != "1" or generator[-1] != "1":
        raise ValueError("CRC generator must start and end with 1.")
    if any(bit not in "01" for bit in generator):
        raise ValueError("CRC generator must contain only 0 and 1.")


def xor_division(bits, generator):
    validate_generator(generator)
    work = list(bits)
    width = len(generator)
    for i in range(len(work) - width + 1):
        if work[i] == "1":
            for j in range(width):
                work[i + j] = str(int(work[i + j]) ^ int(generator[j]))
    return "".join(work[-(width - 1):])


def crc_frame(data, generator="1101"):
    validate_generator(generator)
    remainder = xor_division(data + ("0" * (len(generator) - 1)), generator)
    return data + remainder


def crc_check(frame, generator="1101"):
    validate_generator(generator)
    remainder = xor_division(frame, generator)
    return all(bit == "0" for bit in remainder)


def flip_bit(bits, position):
    if not 0 <= position < len(bits):
        raise ValueError("Bit position is outside the frame.")
    changed = list(bits)
    changed[position] = "1" if changed[position] == "0" else "0"
    return "".join(changed)


def verify_frame(candidate, method, parity_type="even", generator="1101"):
    if method == "parity":
        return parity_check(candidate, parity_type)
    if method == "checksum":
        if len(candidate) < 8:
            return False
        return checksum_check(candidate[:-8], candidate[-8:])
    if method == "crc":
        return crc_check(candidate, generator)
    return False


def main():
    print("=" * 58)
    print(" NETWORK ERROR DETECTION AND LAN PERFORMANCE MONITOR ")
    print("=" * 58)

    message = input("Enter message: ")
    if not message:
        print("Error: Message cannot be empty.")
        return

    data = text_to_bits(message)
    print("\nSENDER DEVICE")
    print("Input message:", message)
    print("Sender data :", data)

    method = input("\nMethod (parity/checksum/crc): ").strip().lower()
    if method not in ("parity", "checksum", "crc"):
        print("Error: Select parity, checksum or crc.")
        return

    parity_type = "even"
    generator = "1101"

    try:
        if method == "parity":
            parity_type = input("Parity (even/odd): ").strip().lower()
            if parity_type not in ("even", "odd"):
                print("Error: Select even or odd parity.")
                return
            frame = parity_frame(data, parity_type)

        elif method == "checksum":
            padded_data, checksum = checksum_frame(data)
            frame = padded_data + checksum
            print("Checksum value:", checksum)

        else:
            chosen_generator = input(
                "CRC generator (press Enter for 1101): "
            ).strip()
            if chosen_generator:
                generator = chosen_generator
            validate_generator(generator)
            frame = crc_frame(data, generator)
            print("CRC generator:", generator)
            print("CRC remainder:", frame[-(len(generator) - 1):])

    except ValueError as error:
        print("Error:", error)
        return

    print("\nTRANSMISSION CHANNEL")
    print("Transmitted frame:", frame)

    received = frame
    inject = input("Inject one bit error? (y/n): ").strip().lower()
    if inject == "y":
        try:
            position = int(input(
                f"Bit position to change (0 to {len(frame) - 1}): "
            ))
            received = flip_bit(frame, position)
        except ValueError as error:
            print("Error:", error)
            return
    elif inject != "n":
        print("Error: Enter y or n.")
        return

    print("Received frame   :", received)

    start_time = perf_counter()
    attempts = 1
    detected_errors = 0
    retransmissions = 0

    if verify_frame(received, method, parity_type, generator):
        status = "SUCCESS - frame accepted"
    else:
        detected_errors = 1
        print("\nERROR DETECTED - frame rejected")
        retry = input("Retransmit original frame? (y/n): ").strip().lower()
        if retry == "y":
            attempts += 1
            retransmissions += 1
            received = frame
            if verify_frame(received, method, parity_type, generator):
                status = "SUCCESS - retransmitted frame accepted"
            else:
                status = "FAILURE - retransmitted frame rejected"
        else:
            status = "FAILURE - frame not delivered"

    elapsed = perf_counter() - start_time
    total_bits = len(frame) * attempts
    throughput = len(data) / elapsed if elapsed > 0 else 0.0

    print("\n" + "=" * 58)
    print(" TRANSMISSION REPORT")
    print("=" * 58)
    print("Detection method       :", method.upper())
    print("Transmission status   :", status)
    print("Transmission attempts :", attempts)
    print("Detected errors       :", detected_errors)
    print("Retransmissions       :", retransmissions)
    print("Frame size             :", len(frame), "bits")
    print("Total bits transmitted:", total_bits, "bits")
    print("Processing time        :", f"{elapsed:.6f} seconds")
    print("Processing throughput :", f"{throughput:.2f} data bits/second")
    print("-" * 58)
    print("Note: This is program-processing throughput,")
    print("not measured physical LAN link throughput.")
    print("=" * 58)


if __name__ == "__main__":
    main()
