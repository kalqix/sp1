#!/usr/bin/env python3
import sys, json, csv

TARGET_MESSAGE = "prove_shard_with_data finished"

def main():
    w = csv.writer(sys.stdout)
    w.writerow(["shard", "total_ms", "total_cells"])

    time_sum = 0
    cells_sum = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Not JSON (e.g., cargo noise) -> skip
            continue

        if obj.get("message") != TARGET_MESSAGE:
            continue

        shard = obj.get("shard")
        total_ms = obj.get("total_ms")
        total_cells = obj.get("total_cells")

        shard_num = int(shard)
        total_ms_num = int(total_ms)
        total_cells_num = int(total_cells)

        time_sum += total_ms_num
        cells_sum += total_cells_num

        w.writerow([shard_num, total_ms_num, total_cells_num])

    # Write the totals row
    w.writerow(["total", time_sum, cells_sum])

if __name__ == "__main__":
    main()