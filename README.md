# OPAL (WIP)

Command line tools and library for controlling Opal disk drives using Linux IOCTLs with [sedutil](https://github.com/Drive-Trust-Alliance/sedutil) compatibility layer.

## Requirements

Different IOCTLs were added in different kernel versions, the most notable in 4.14 so make sure your kernel is not that old.

`CONFIG_BLK_SED_OPAL` kernel parameter must be enabled:

```bash
zcat /proc/config.gz | grep CONFIG_BLK_SED_OPAL
```

## `sedutil` compatibility

By default `opalctl` uses password hashing just like `sedutil` does. Instead of sending a raw password to a device it's PBKDF2'd first.

Passwords are obtained from `-pwdfile=PATH` option, `OPAL_PASSWORD` environment variable, prompted from `TTY` or read from `STDIN` (in this very order) and not accepted as an argument due to security issues.

If you use a `sedutil` fork ([1](https://github.com/ChubbyAnt/sedutil), [2](https://github.com/ladar/sedutil)) that switched to SHA512 password hashing algorithm use `-sha512` option.

To use raw passwords pass `-raw` option with `-hex` if needed.

## Usage

### Unlock After Suspend

To enable drive unlocking after a suspend of a device previously encrypted with `sedutil`:

```bash
opalctl save <device> RW
``` 
