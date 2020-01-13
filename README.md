# OPAL (WIP)

Command line tools and library for controlling Opal disk drives using Linux IOCTLs.

## Requirements

Different IOCTLs were added in different kernel versions, the most notable `IOC_OPAL_SAVE` in 4.14 so make sure your kernel is not that old.

`CONFIG_BLK_SED_OPAL` kernel parameter must be enabled:

```bash
zcat /proc/config.gz | grep CONFIG_BLK_SED_OPAL
```

## Usage

`opalctl` operates on low-level but provides compatibility layer for [`sedutil`](https://github.com/Drive-Trust-Alliance/sedutil) that hashes passwords with [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) before sending them to the drive.

For example to enable drive unlocking after a suspend of a device previously set up with `opalctl` it's needed to get the hashed version of a password:

```bash
opalctl hash nvme0n1 PASSWORD
opalctl save -hex nvme0n1 HASH
``` 

To get your device NAME run `lsblk -d -o NAME,SIZE`:

```
NAME      SIZE
sda      1024G
nvme0n1   512G
```
