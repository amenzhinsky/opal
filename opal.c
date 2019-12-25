#include <linux/sed-opal.h>
#include <sys/ioctl.h>

// https://github.com/torvalds/linux/blob/v5.4/block/sed-opal.c#L248
static const char *const opal_errors[] = {
    "Success",
    "Not Authorized",
    "Unknown Error",
    "SP Busy",
    "SP Failed",
    "SP Disabled",
    "SP Frozen",
    "No Sessions Available",
    "Uniqueness Conflict",
    "Insufficient Space",
    "Insufficient Rows",
    "Invalid Function",
    "Invalid Parameter",
    "Invalid Reference",
    "Unknown Error",
    "TPER Malfunction",
    "Transaction Failure",
    "Response Overflow",
    "Authority Locked Out",
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ((unsigned int)(sizeof(x) / sizeof(*x)))
#endif

const char *opal_error_to_human(int error) {
  if (error == 0x3f) {
    return "Failed";
  }
  if (error >= ARRAY_SIZE(opal_errors) || error < 0) {
    return "Unknown Error";
  }
  return opal_errors[error];
}

int opal_save(int fd, struct opal_lock_unlock *lkul) {
  return ioctl(fd, IOC_OPAL_SAVE, lkul);
}

int opal_lock_unlock(int fd, struct opal_lock_unlock *lkul) {
  return ioctl(fd, IOC_OPAL_LOCK_UNLOCK, lkul);
}

int opal_take_ownership(int fd, struct opal_key *key) {
  return ioctl(fd, IOC_OPAL_TAKE_OWNERSHIP, key);
}

int opal_activate_lsp(int fd, struct opal_lr_act *act) {
  return ioctl(fd, IOC_OPAL_ACTIVATE_LSP, act);
}

int opal_set_pw(int fd, struct opal_new_pw *pw) {
  return ioctl(fd, IOC_OPAL_SET_PW, pw);
}

int opal_activate_usr(int fd, struct opal_session_info *si) {
  return ioctl(fd, IOC_OPAL_ACTIVATE_USR, si);
}

int opal_revert_tpr(int fd, struct opal_key *key) {
  return ioctl(fd, IOC_OPAL_REVERT_TPR, key);
}

int opal_lr_setup(int fd, struct opal_user_lr_setup *lrs) {
  return ioctl(fd, IOC_OPAL_LR_SETUP, lrs);
}

int opal_add_usr_to_lr(int fd, struct opal_lock_unlock *lkul) {
  return ioctl(fd, IOC_OPAL_ADD_USR_TO_LR, lkul);
}

int opal_enable_disable_mbr(int fd, struct opal_mbr_data *mbr) {
  return ioctl(fd, IOC_OPAL_ENABLE_DISABLE_MBR, mbr);
}

int opal_erase_lr(int fd, struct opal_session_info *si) {
  return ioctl(fd, IOC_OPAL_ERASE_LR, si);
}

int opal_secure_erase_lr(int fd, struct opal_session_info *si) {
  return ioctl(fd, IOC_OPAL_SECURE_ERASE_LR, si);
}

int opal_psid_revert_tpr(int fd, struct opal_key *key) {
  return ioctl(fd, IOC_OPAL_PSID_REVERT_TPR, key);
}

int opal_mbr_done(int fd, struct opal_mbr_done *mbr) {
  return ioctl(fd, IOC_OPAL_MBR_DONE, mbr);
}

int opal_write_shadow_mbr(int fd, struct opal_shadow_mbr *mbr) {
  return ioctl(fd, IOC_OPAL_WRITE_SHADOW_MBR, mbr);
}
