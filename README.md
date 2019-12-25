# OPAL

To get your device NAME run `lsblk` and find the corresponding record with `disk` type:

```
NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
nvme0n1     259:0    0   477G  0 disk
├─nvme0n1p1 259:1    0   512M  0 part /boot
└─nvme0n1p2 259:2    0 476.4G  0 part /
```

It's `nvme0n1` in this example.
