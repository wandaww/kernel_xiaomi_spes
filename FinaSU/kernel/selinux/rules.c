#include "linux/rcupdate.h"
#include "security.h"
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/lockdep.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "uapi/selinux.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#include "ss/sidtab.h"
#include "linux/lsm_audit.h" // IWYU pragma: keep
#include "xfrm.h"

struct selinux_policy *backup_sepolicy;

#define SELINUX_POLICY_INSTEAD_SELINUX_SS

#define ALL NULL

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif
// reset avc cache table, otherwise the new rules will not take effect if already denied
static void reset_avc_cache(u32 seqno)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
    avc_ss_reset(seqno);
    selnl_notify_policyload(seqno);
    selinux_status_update_policyload(seqno);
#else
    struct selinux_avc *avc = selinux_state.avc;
    avc_ss_reset(avc, seqno);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(&selinux_state, seqno);
#endif
    selinux_xfrm_notify_policyload();
}

void apply_kernelsu_rules()
{
    struct selinux_ss *ss = selinux_state.ss;
    struct selinux_policy cur_policy = {};
    struct selinux_policy *pol;
    struct policydb old_policydb;
    struct policydb *db;
    u32 seqno;

    if (!ss) {
        pr_err("SELinux state is not initialized\n");
        return;
    }

    if (!getenforce())
        pr_info("SELinux permissive or disabled, apply rules!\n");

    /*
     * Snapshot the 4.19 SELinux policy. FinaSU's policy duplication
     * routine serializes policydb and reconstructs an independent copy.
     */
    cur_policy.policydb = ss->policydb;
    cur_policy.sidtab = ss->sidtab;
    cur_policy.latest_granting = ss->latest_granting;

    backup_sepolicy = ksu_dup_sepolicy(&cur_policy);
    if (IS_ERR(backup_sepolicy)) {
        pr_err("failed to create backup sepolicy: %ld\n",
               PTR_ERR(backup_sepolicy));
        backup_sepolicy = NULL;
    } else {
        backup_sepolicy->sidtab =
            kzalloc(sizeof(*backup_sepolicy->sidtab), GFP_KERNEL);

        if (!backup_sepolicy->sidtab) {
            pr_err("failed to alloc backup sidtab\n");
            ksu_destroy_sepolicy(backup_sepolicy);
            backup_sepolicy = NULL;
        } else {
            int ret = policydb_load_isids(&backup_sepolicy->policydb,
                                          backup_sepolicy->sidtab);
            if (ret) {
                pr_err("failed to load isids for backup sepolicy: %d!\n",
                       ret);
                kfree(backup_sepolicy->sidtab);
                ksu_destroy_sepolicy(backup_sepolicy);
                backup_sepolicy = NULL;
            } else {
                pr_info("backup sepolicy success! latest_granting=%d\n",
                        backup_sepolicy->latest_granting);
            }
        }
    }

    pol = ksu_dup_sepolicy(&cur_policy);
    if (IS_ERR(pol)) {
        pr_err("failed to dup selinux policy: %ld\n", PTR_ERR(pol));
        return;
    }

    db = &pol->policydb;

    ksu_type(db, KERNEL_SU_DOMAIN, "domain");
    ksu_permissive(db, KERNEL_SU_DOMAIN);
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain");

    ksu_type(db, KERNEL_SU_FILE, "file_type");
    ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");
    ksu_allow(db, "domain", KERNEL_SU_FILE, ALL, ALL);
    ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);

    if (db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL);
    }

    ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "read");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "process", "getattr");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "process", "sigchld");

    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "getattr");

    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fd", "use");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "write");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "read");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "open");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "getattr");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "read");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "write");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "connectto");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "getopt");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "getattr");

    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "execute");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "getattr");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "map");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "read");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "write");

    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process", "getattr");

    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "binder", ALL);
    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

#ifdef CONFIG_KSU_SUSFS
    ksu_allow(db, "zygote", "labeledfs", "filesystem", "unmount");
#endif

    /*
     * Install the modified policydb using the 4.19 SELinux policy lock.
     * Abort if the active policy changed since the snapshot was taken.
     */
    write_lock_irq(&ss->policy_rwlock);
    if (ss->latest_granting != cur_policy.latest_granting) {
        write_unlock_irq(&ss->policy_rwlock);
        pr_err("SELinux policy changed during KernelSU policy update\n");
        ksu_destroy_sepolicy(pol);
        return;
    }

    memcpy(&old_policydb, &ss->policydb, sizeof(old_policydb));
    memcpy(&ss->policydb, &pol->policydb, sizeof(ss->policydb));
    memset(&pol->policydb, 0, sizeof(pol->policydb));
    seqno = ++ss->latest_granting;
    write_unlock_irq(&ss->policy_rwlock);

    policydb_destroy(&old_policydb);
    kfree(pol);

    reset_avc_cache(seqno);

#ifdef CONFIG_KSU_SUSFS
    susfs_set_batch_sid();
#endif
}

#define KSU_SEPOLICY_MAX_BATCH_SIZE (8U * 1024U * 1024U)
#define KSU_SEPOLICY_MAX_ARGS 5

struct sepol_data {
    u32 cmd;
    u32 subcmd;
};

struct sepol_batch_cursor {
    const u8 *cur;
    const u8 *end;
};

static size_t sepol_remaining(const struct sepol_batch_cursor *cursor)
{
    return (size_t)(cursor->end - cursor->cur);
}

static int sepol_read_cmd_header(struct sepol_batch_cursor *cursor, struct sepol_data *header)
{
    if (sepol_remaining(cursor) < sizeof(*header)) {
        return -EINVAL;
    }

    memcpy(header, cursor->cur, sizeof(*header));
    cursor->cur += sizeof(*header);

    return 0;
}

static int sepol_read_string(struct sepol_batch_cursor *cursor, const char **out)
{
    u32 len;
    const char *str;

    if (sepol_remaining(cursor) < sizeof(len)) {
        return -EINVAL;
    }

    memcpy(&len, cursor->cur, sizeof(len));
    cursor->cur += sizeof(len);

    if (len >= sepol_remaining(cursor)) {
        return -EINVAL;
    }

    str = (const char *)cursor->cur;
    if (memchr(str, '\0', len) != NULL || str[len] != '\0') {
        return -EINVAL;
    }

    cursor->cur += len + 1;
    if (len == 0) {
        *out = ALL;
        return 0;
    }

    *out = str;
    return 0;
}

static int sepol_require_not_all(const char *value, const char *name)
{
    if (value != ALL) {
        return 0;
    }

    pr_err("sepol: %s cannot be ALL.\n", name);
    return -EINVAL;
}

static int sepol_expected_argc(u32 cmd)
{
    switch (cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        return 4;
    case KSU_SEPOLICY_CMD_XPERM:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_STATE:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        return 2;
    case KSU_SEPOLICY_CMD_ATTR:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE_TRANSITION:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        return 4;
    case KSU_SEPOLICY_CMD_GENFSCON:
        return 3;
    default:
        return -EINVAL;
    }
}

static int apply_one_sepolicy_cmd(struct policydb *db, const struct sepol_data *header, const char **args)
{
    bool success = false;
    int ret;

    switch (header->cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW) {
            success = ksu_allow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY) {
            success = ksu_deny(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW) {
            success = ksu_auditallow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT) {
            success = ksu_dontaudit(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_XPERM:
        ret = sepol_require_not_all(args[3], "operation");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[4], "perm_set");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_ALLOW) {
            success = ksu_allowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_AUDITALLOW) {
            success = ksu_auditallowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_DONTAUDIT) {
            success = ksu_dontauditxperm(db, args[0], args[1], args[2], args[4]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_TYPE_STATE:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE) {
            success = ksu_permissive(db, args[0]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE) {
            success = ksu_enforce(db, args[0]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (header->cmd == KSU_SEPOLICY_CMD_TYPE) {
            success = ksu_type(db, args[0], args[1]);
        } else {
            success = ksu_typeattribute(db, args[0], args[1]);
        }
        if (!success) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case KSU_SEPOLICY_CMD_ATTR:
        ret = sepol_require_not_all(args[0], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_attribute(db, args[0])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case KSU_SEPOLICY_CMD_TYPE_TRANSITION: {
        const char *object = ALL;

        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        object = args[4];

        success = ksu_type_transition(db, args[0], args[1], args[2], args[3], object);
        return success ? 0 : -EINVAL;
    }

    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_CHANGE) {
            success = ksu_type_change(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_MEMBER) {
            success = ksu_type_member(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_GENFSCON:
        ret = sepol_require_not_all(args[0], "name");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "path");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "context");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_genfscon(db, args[0], args[1], args[2])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    default:
        pr_err("sepol: unknown cmd: %d\n", header->cmd);
        return -EINVAL;
    }
}

static struct selinux_policy *ksu_dup_current_sepolicy(
    struct selinux_state *state, u32 *snapshot_seqno)
{
    struct selinux_policy *pol;
    struct policy_file fp;
    struct policydb *db = &state->ss->policydb;
    void *data;
    size_t alloc_len, len;
    u32 seqno, nprim;
    bool android_netlink_route;
    bool android_netlink_getneigh;
    int ret;

    for (;;) {
        read_lock(&state->ss->policy_rwlock);
        alloc_len = db->len +
            (size_t)db->p_types.nprim * (sizeof(u32) + sizeof(u64));
        seqno = state->ss->latest_granting;
        nprim = db->p_types.nprim;
        read_unlock(&state->ss->policy_rwlock);

        data = vmalloc(alloc_len);
        if (!data)
            return ERR_PTR(-ENOMEM);

        read_lock(&state->ss->policy_rwlock);

        if (seqno != state->ss->latest_granting ||
            nprim != db->p_types.nprim ||
            alloc_len < db->len +
                (size_t)db->p_types.nprim * (sizeof(u32) + sizeof(u64))) {
            read_unlock(&state->ss->policy_rwlock);
            vfree(data);
            continue;
        }

        fp.data = data;
        fp.len = alloc_len;

        ret = policydb_write(db, &fp);

        android_netlink_route = db->android_netlink_route;
        android_netlink_getneigh = db->android_netlink_getneigh;

        read_unlock(&state->ss->policy_rwlock);

        if (ret) {
            kvfree(data);
            return ERR_PTR(ret);
        }

        len = alloc_len - fp.len;
        break;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    if (len >= 24) {
        u32 *config_ptr = (u32 *)((unsigned long)data + 20);

        if (android_netlink_route)
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;

        if (android_netlink_getneigh)
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
    }
#endif

    pol = kzalloc(sizeof(*pol), GFP_KERNEL);
    if (!pol) {
        kvfree(data);
        return ERR_PTR(-ENOMEM);
    }

    pol->latest_granting = seqno;
    memset(&pol->policydb, 0, sizeof(pol->policydb));

    fp.data = data;
    fp.len = len;

    ret = policydb_read(&pol->policydb, &fp);
    kvfree(data);

    if (ret) {
        kfree(pol);
        return ERR_PTR(ret);
    }

    pol->policydb.len = len;
    *snapshot_seqno = seqno;

    return pol;
}

int handle_sepolicy(void __user *user_data, u64 data_len)
{
    struct selinux_ss *ss = selinux_state.ss;
    struct selinux_policy *pol;
    struct policydb *old_policydb;
    struct policydb *db;
    struct sepol_batch_cursor cursor;
    u8 *payload;
    u32 snapshot_seqno;
    u32 seqno;
    int ret;
    int success_cmd_count = 0;
    u32 cmd_index = 0;

    if (!user_data || !data_len)
        return -EINVAL;

    if (data_len > KSU_SEPOLICY_MAX_BATCH_SIZE)
        return -E2BIG;

    if (!ss)
        return -EINVAL;

    payload = kvmalloc((size_t)data_len, GFP_KERNEL);
    if (!payload)
        return -ENOMEM;

    if (copy_from_user(payload, user_data, (size_t)data_len)) {
        ret = -EFAULT;
        goto out_free;
    }

    if (!getenforce())
        pr_info("SELinux permissive or disabled when handle policy!\n");

    pol = ksu_dup_current_sepolicy(&selinux_state, &snapshot_seqno);
    if (IS_ERR(pol)) {
        ret = PTR_ERR(pol);
        pr_err("ksu_dup_current_sepolicy failed: %d\n", ret);
        goto out_free;
    }

    db = &pol->policydb;
    cursor.cur = payload;
    cursor.end = payload + (size_t)data_len;

    while (cursor.cur < cursor.end) {
        struct sepol_data header;
        const char *args[KSU_SEPOLICY_MAX_ARGS] = { 0 };
        int expected_argc;
        u32 arg_index;

        ret = sepol_read_cmd_header(&cursor, &header);
        if (ret < 0) {
            pr_err("sepol: failed to read cmd header #%u\n",
                   cmd_index);
            goto out_drop_new_policy;
        }

        expected_argc = sepol_expected_argc(header.cmd);
        if (expected_argc < 0 ||
            expected_argc > KSU_SEPOLICY_MAX_ARGS) {
            ret = -EINVAL;
            pr_err("sepol: invalid cmd header #%u\n", cmd_index);
            goto out_drop_new_policy;
        }

        for (arg_index = 0; arg_index < (u32)expected_argc;
             arg_index++) {
            ret = sepol_read_string(&cursor, &args[arg_index]);
            if (ret < 0) {
                pr_err("sepol: failed to read cmd #%u arg #%u\n",
                       cmd_index, arg_index);
                goto out_drop_new_policy;
            }
        }

        ret = apply_one_sepolicy_cmd(db, &header, args);
        if (ret < 0) {
            pr_err("sepol: cmd #%u failed, cmd=%u subcmd=%u\n",
                   cmd_index, header.cmd, header.subcmd);
        } else {
            success_cmd_count++;
        }

        cmd_index++;
    }

    old_policydb = kzalloc(sizeof(*old_policydb), GFP_KERNEL);
    if (!old_policydb) {
        ret = -ENOMEM;
        goto out_drop_new_policy;
    }

    write_lock_irq(&ss->policy_rwlock);

    if (ss->latest_granting != snapshot_seqno) {
        write_unlock_irq(&ss->policy_rwlock);
        kfree(old_policydb);
        ret = -EAGAIN;
        pr_warn("sepol: policy changed during modification\n");
        goto out_drop_new_policy;
    }

    memcpy(old_policydb, &ss->policydb, sizeof(*old_policydb));
    memcpy(&ss->policydb, &pol->policydb, sizeof(ss->policydb));
    memset(&pol->policydb, 0, sizeof(pol->policydb));

    seqno = ++ss->latest_granting;

    write_unlock_irq(&ss->policy_rwlock);

    kfree(pol);
    policydb_destroy(old_policydb);
    kfree(old_policydb);

    reset_avc_cache(seqno);

#ifdef CONFIG_KSU_SUSFS
    susfs_set_batch_sid();
#endif

    ret = success_cmd_count;
    goto out_free;

out_drop_new_policy:
    ksu_destroy_sepolicy(pol);

out_free:
    kvfree(payload);
    return ret;
}
