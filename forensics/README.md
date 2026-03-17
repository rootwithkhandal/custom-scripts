# forensics/

Forensic tools for disk imaging and disk image analysis.

## Scripts

| Script | Description |
|--------|-------------|
| `disk_imaging.py` | Forensic disk imaging — live progress, gzip compression, multi-algo hash verification, rich TUI |
| `disk_reader.py` | Disk image tool — mount/unmount/browse/extract/info for `.img`, `.img.gz`, `.iso` |

---

## Requirements

```bash
pip install rich
```

System tools:

```bash
pkg install util-linux    # Termux (lsblk, blockdev)
apt install util-linux    # Debian/Ubuntu
```

Both scripts require root for most operations.

---

## disk_imaging.py

Creates a forensic image of a block device using `dd`. Supports gzip compression and hash verification.

```bash
# interactive mode — prompts for device, output path, options
sudo python3 disk_imaging.py

# specify source and output
sudo python3 disk_imaging.py -s /dev/sda -o /mnt/backup/disk.img

# with gzip compression
sudo python3 disk_imaging.py -s /dev/sdb -o disk.img.gz --compress

# with specific hash algorithm
sudo python3 disk_imaging.py -s /dev/sda -o disk.img --hash sha512

# skip hash verification
sudo python3 disk_imaging.py -s /dev/sda -o disk.img --no-verify

# custom block size
sudo python3 disk_imaging.py -s /dev/sda -o disk.img -b 8M
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-s` | interactive | Source device (e.g. `/dev/sda`) |
| `-o` | interactive | Output image path |
| `-b` | `4M` | Block size (`512`, `1M`, `4M`, `8M`, `16M`) |
| `--compress` | off | Compress output with gzip |
| `--hash` | `sha256` | Hash algorithm: `md5` `sha1` `sha256` `sha512` |
| `--no-verify` | off | Skip hash verification after imaging |

Hash is saved alongside the image as `<image>.<algo>` (e.g. `disk.img.sha256`).
Log saved to `~/disk_imaging.log`.

---

## disk_reader.py

Mount, browse, extract files from, and analyse disk images. Supports `.img`, `.img.gz`, `.iso`.

```bash
# interactive menu
sudo python3 disk_reader.py

# mount image (read-only by default)
sudo python3 disk_reader.py mount disk.img /mnt/img

# mount gzip image
sudo python3 disk_reader.py mount disk.img.gz /mnt/img

# mount read-write
sudo python3 disk_reader.py mount disk.img /mnt/img --rw

# mount with explicit filesystem type
sudo python3 disk_reader.py mount disk.img /mnt/img --fs ext4

# unmount
sudo python3 disk_reader.py unmount /mnt/img

# browse directory tree (default depth 2)
sudo python3 disk_reader.py browse /mnt/img
sudo python3 disk_reader.py browse /mnt/img --depth 4

# extract all files
sudo python3 disk_reader.py extract /mnt/img ~/output

# extract by pattern
sudo python3 disk_reader.py extract /mnt/img ~/output --pattern '*.log'
sudo python3 disk_reader.py extract /mnt/img ~/output --pattern '*.conf'

# show image info and SHA256
sudo python3 disk_reader.py info disk.img

# list active loop-device mounts
sudo python3 disk_reader.py mounts
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `mount <image> <mountpoint>` | Mount disk image |
| `unmount <mountpoint>` | Unmount and clean up |
| `browse <mountpoint>` | Print directory tree |
| `extract <mountpoint> <dest>` | Copy files out |
| `info <image>` | Show size, type, SHA256 |
| `mounts` | List active loop mounts |

Log saved to `~/disk_reader.log`.
