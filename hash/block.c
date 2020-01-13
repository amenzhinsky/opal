#include <linux/nvme_ioctl.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>

static int scsi_get_serial(int fd, unsigned char serial[20]) {
  // hdparm --verbose -I /dev/sda 2>&1 | grep cdb | head -1
  unsigned char cdb[16] = {
      0x85, 0x08, 0x0e, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xec, 0x00,
  };
  unsigned char sb[32];
  unsigned short dxfer[256];

  struct sg_io_hdr hdr = {
      .interface_id = 'S',
      .mx_sb_len = sizeof(sb),
      .sbp = sb,
      .dxfer_direction = SG_DXFER_FROM_DEV,
      .dxfer_len = sizeof(dxfer),
      .dxferp = dxfer,
      .cmd_len = sizeof(cdb),
      .cmdp = cdb,
      .timeout = 15000,
  };

  int ret = ioctl(fd, SG_IO, &hdr);
  if (ret != 0) {
    return ret;
  }
  if (hdr.status || hdr.host_status || hdr.driver_status) {
    return -1;
  }

  for (int i = 0; i < 10; i++) {
    serial[i * 2] = dxfer[10 + i] >> 8;
    serial[i * 2 + 1] = dxfer[10 + i];
  }
  return 0;
}

static int nvme_get_serial(int fd, unsigned char serial[20]) {
  unsigned char data[4096];
  struct nvme_admin_cmd cmd = {
      .opcode = 0x06, // nvme_admin_identify
      .addr = (long long unsigned int)data,
      .data_len = sizeof(data),
      .cdw10 = 1,
  };

  int ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
  if (ret != 0) {
    return ret;
  }

  for (int i = 0; i < 20; i++) {
    serial[i] = data[i + 4];
  }
  return 0;
}

int get_serial(int fd, unsigned char serial[20]) {
  int ret = nvme_get_serial(fd, serial);
  if (ret == 0) {
    return 0;
  }
  return scsi_get_serial(fd, serial);
}
