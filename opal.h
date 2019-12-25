#include <linux/sed-opal.h>

const char *opal_error_to_human(int error);

int opal_save(int fd, struct opal_lock_unlock *lkul);
int opal_lock_unlock(int fd, struct opal_lock_unlock *lkul);
int opal_take_ownership(int fd, struct opal_key *key);
int opal_activate_lsp(int fd, struct opal_lr_act *act);
int opal_set_pw(int fd, struct opal_new_pw *pw);
int opal_activate_usr(int fd, struct opal_session_info *si);
int opal_revert_tpr(int fd, struct opal_key *key);
int opal_lr_setup(int fd, struct opal_user_lr_setup *lrs);
int opal_add_usr_to_lr(int fd, struct opal_lock_unlock *lkul);
int opal_enable_disable_mbr(int fd, struct opal_mbr_data *mbr);
int opal_erase_lr(int fd, struct opal_session_info *si);
int opal_secure_erase_lr(int fd, struct opal_session_info *si);
int opal_psid_revert_tpr(int fd, struct opal_key *key);
int opal_mbr_done(int fd, struct opal_mbr_done *mbr);
int opal_write_shadow_mbr(int fd, struct opal_shadow_mbr *mbr);
