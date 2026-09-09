/* ====================================================================
   macOS SECURITY MODEL SIMULATION -- POSIX + ACLs + Sandbox
   ====================================================================
   This program simulates the core concepts behind Apple macOS's
   LAYERED security model. It is NOT a real operating system -- it is
   a simplified software MODEL built to demonstrate the underlying
   ideas and how they DIFFER from Windows:

     LAYER 1 -- POSIX (UNIX) PERMISSION BITS (the foundation)
       Every file has an owner UID, a group GID, and three sets of
       rwx bits: owner / group / other. This is the classic Unix
       model inherited from BSD, and macOS checks it FIRST.

     LAYER 2 -- ACCESS CONTROL LISTS (fine-grained overrides)
       Since macOS 10.4, HFS+/APFS support NFSv4-style ACLs that
       can ALLOW or DENY specific users/groups specific rights.
       macOS evaluates ACLs BEFORE falling back to POSIX bits:
         a) Walk ACEs top-to-bottom.
         b) First matching DENY -> access denied immediately.
         c) First matching ALLOW -> access granted immediately.
         d) If no ACE matches -> fall through to POSIX bits.

     LAYER 3 -- SANDBOX / ENTITLEMENTS (App Sandbox / TCC)
       Even if POSIX + ACL would grant access, macOS can STILL block
       it if the process's sandbox profile / entitlements do not allow
       that resource category. This is how macOS protects Desktop,
       Documents, Camera, Microphone, etc. via the TCC framework.
       In our simulation we model this as a simple set of
       "entitlement" strings attached to each process.

     KEY DIFFERENCE FROM WINDOWS:
       Windows: ACL is the ONLY gatekeeper (no POSIX bits).
       macOS:   THREE layers stack -- Sandbox -> ACL -> POSIX. All
                three must agree before access is granted.

   SIMPLIFICATIONS:
     - Real macOS NFSv4 ACLs have inheritance flags, audit entries,
       and more granular rights; we use a simplified subset.
     - Real sandbox profiles are compiled from Scheme-like DSL files;
       we model them as a set of allowed resource-category strings.
     - We focus on demonstrating the LAYERED evaluation clearly.
   ==================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------- Limits --------------------------- */
#define MAX_GROUPS        8
#define MAX_ACES         16
#define MAX_RESOURCES    10
#define MAX_PROCESSES    10
#define MAX_USERS         8
#define MAX_ALL_GROUPS    8
#define MAX_ENTITLEMENTS  8
#define ENTITLE_LEN      48

/* ------- Access-right bit flags ------- */
#define RIGHT_READ        0x01
#define RIGHT_WRITE       0x02
#define RIGHT_EXECUTE     0x04
#define RIGHT_DELETE      0x08

/* ------- POSIX permission bits (rwx for owner/group/other) ------- */
#define POSIX_OWN_R  0400
#define POSIX_OWN_W  0200
#define POSIX_OWN_X  0100
#define POSIX_GRP_R  0040
#define POSIX_GRP_W  0020
#define POSIX_GRP_X  0010
#define POSIX_OTH_R  0004
#define POSIX_OTH_W  0002
#define POSIX_OTH_X  0001

/* ------- Root UID (macOS inherits UID 0 = superuser from BSD) ------- */
#define ROOT_UID 0

/* ------- ACE type ------- */
typedef enum { ACE_ALLOW, ACE_DENY } AceType;

/* ------- Data structures ------- */

typedef struct {
    int  gid;
    char name[32];
} Group;

typedef struct {
    int  uid;
    char name[32];
    int  group_ids[MAX_GROUPS];
    int  group_count;
} User;

typedef struct {
    AceType type;
    int     sid;
    int     is_group;
    int     rights;
} ACE;

typedef struct {
    ACE entries[MAX_ACES];
    int count;
} ACL;

typedef struct {
    char name[64];
    int  owner_uid;
    int  owner_gid;
    int  posix_mode;
    ACL  acl;
    char category[32];
} Resource;

typedef struct {
    int  pid;
    char name[32];
    int  uid;
    int  group_ids[MAX_GROUPS];
    int  group_count;
    char entitlements[MAX_ENTITLEMENTS][ENTITLE_LEN];
    int  entitlement_count;
} Process;

/* -------------------- Global data stores -------------------- */
Group    groups[MAX_ALL_GROUPS];
int      group_count = 0;

User     users[MAX_USERS];
int      user_count = 0;

Resource resources[MAX_RESOURCES];
int      resource_count = 0;

Process  processes[MAX_PROCESSES];
int      process_count = 0;

/* ----------------- Safe Input Helper (Prevents Infinite Loops) ----------------- */
int read_int_safe(int *out) {
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0; /* EOF */
    }
    if (sscanf(line, "%d", out) == 1) {
        return 1; /* Success */
    }
    return -1; /* Invalid */
}

int read_octal_safe(int *out) {
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0; /* EOF */
    }
    if (sscanf(line, "%o", out) == 1) {
        return 1; /* Success */
    }
    return -1; /* Invalid */
}

/* ---------------- Helper: rights -> string ---------------- */
void rights_to_string(int rights, char *buf, int bufsize) {
    buf[0] = '\0';
    if (rights & RIGHT_READ)    strncat(buf, "READ ",    bufsize - (int)strlen(buf) - 1);
    if (rights & RIGHT_WRITE)   strncat(buf, "WRITE ",   bufsize - (int)strlen(buf) - 1);
    if (rights & RIGHT_EXECUTE) strncat(buf, "EXECUTE ", bufsize - (int)strlen(buf) - 1);
    if (rights & RIGHT_DELETE)  strncat(buf, "DELETE ",  bufsize - (int)strlen(buf) - 1);
    int len = (int)strlen(buf);
    if (len > 0 && buf[len - 1] == ' ') buf[len - 1] = '\0';
}

void mode_to_string(int mode, char *buf) {
    buf[0] = (mode & POSIX_OWN_R) ? 'r' : '-';
    buf[1] = (mode & POSIX_OWN_W) ? 'w' : '-';
    buf[2] = (mode & POSIX_OWN_X) ? 'x' : '-';
    buf[3] = (mode & POSIX_GRP_R) ? 'r' : '-';
    buf[4] = (mode & POSIX_GRP_W) ? 'w' : '-';
    buf[5] = (mode & POSIX_GRP_X) ? 'x' : '-';
    buf[6] = (mode & POSIX_OTH_R) ? 'r' : '-';
    buf[7] = (mode & POSIX_OTH_W) ? 'w' : '-';
    buf[8] = (mode & POSIX_OTH_X) ? 'x' : '-';
    buf[9] = '\0';
}

const char *group_name(int gid) {
    for (int i = 0; i < group_count; i++)
        if (groups[i].gid == gid) return groups[i].name;
    return "???";
}

const char *user_name(int uid) {
    for (int i = 0; i < user_count; i++)
        if (users[i].uid == uid) return users[i].name;
    return "???";
}

void print_separator(void) {
    printf("------------------------------------------------------------------------\n");
}

/* ================================================================
   LAYER 3 -- SANDBOX / ENTITLEMENT CHECK (checked FIRST)
   ================================================================ */
int sandbox_check(const Process *proc, const Resource *res,
                  char *reason, int reason_size)
{
    if (res->category[0] == '\0') {
        snprintf(reason, reason_size,
                 "Sandbox: resource has no sandbox category -- PASS");
        return 1;
    }
    for (int i = 0; i < proc->entitlement_count; i++) {
        if (strcmp(proc->entitlements[i], res->category) == 0) {
            snprintf(reason, reason_size,
                     "Sandbox: process has entitlement \"%s\" -- PASS",
                     res->category);
            return 1;
        }
    }
    snprintf(reason, reason_size,
             "Sandbox: process LACKS entitlement \"%s\" -- BLOCKED",
             res->category);
    return 0;
}

/* ================================================================
   LAYER 2 -- ACL CHECK (checked SECOND)
   ================================================================ */
int ace_matches(const ACE *ace, const Process *proc) {
    if (!ace->is_group)
        return (ace->sid == proc->uid);
    for (int i = 0; i < proc->group_count; i++)
        if (proc->group_ids[i] == ace->sid) return 1;
    return 0;
}

int acl_check(const Process *proc, const Resource *res, int req_rights,
              char *reason, int reason_size)
{
    const ACL *acl = &res->acl;
    if (acl->count == 0) {
        snprintf(reason, reason_size,
                 "ACL: no ACL entries present -- fall through to POSIX");
        return -1;
    }

    for (int i = 0; i < acl->count; i++) {
        const ACE *a = &acl->entries[i];
        if (!ace_matches(a, proc)) continue;

        if (a->type == ACE_DENY && (a->rights & req_rights)) {
            const char *who = a->is_group ? group_name(a->sid) : user_name(a->sid);
            char dbuf[128];
            rights_to_string(a->rights & req_rights, dbuf, sizeof(dbuf));
            snprintf(reason, reason_size,
                     "ACL: DENY ACE #%d for %s matched [%s] -- DENIED",
                     i + 1, who, dbuf);
            return 0;
        }
        if (a->type == ACE_ALLOW && (a->rights & req_rights) == req_rights) {
            const char *who = a->is_group ? group_name(a->sid) : user_name(a->sid);
            snprintf(reason, reason_size,
                     "ACL: ALLOW ACE #%d for %s matched -- GRANTED",
                     i + 1, who);
            return 1;
        }
    }

    snprintf(reason, reason_size,
             "ACL: no matching ACE for requested rights -- fall through to POSIX");
    return -1;
}

/* ================================================================
   LAYER 1 -- POSIX PERMISSION CHECK (checked LAST)
   ================================================================ */
int posix_check(const Process *proc, const Resource *res, int req_rights,
                char *reason, int reason_size)
{
    int mode = res->posix_mode;
    int effective_bits = 0;

    if (proc->uid == ROOT_UID) {
        snprintf(reason, reason_size,
                 "POSIX: process runs as root (UID 0) -- BYPASS GRANTED");
        return 1;
    }

    if (proc->uid == res->owner_uid) {
        if (mode & POSIX_OWN_R) effective_bits |= RIGHT_READ;
        if (mode & POSIX_OWN_W) effective_bits |= (RIGHT_WRITE | RIGHT_DELETE);
        if (mode & POSIX_OWN_X) effective_bits |= RIGHT_EXECUTE;
    } else {
        int in_group = 0;
        for (int i = 0; i < proc->group_count; i++)
            if (proc->group_ids[i] == res->owner_gid) { in_group = 1; break; }

        if (in_group) {
            if (mode & POSIX_GRP_R) effective_bits |= RIGHT_READ;
            if (mode & POSIX_GRP_W) effective_bits |= (RIGHT_WRITE | RIGHT_DELETE);
            if (mode & POSIX_GRP_X) effective_bits |= RIGHT_EXECUTE;
        } else {
            if (mode & POSIX_OTH_R) effective_bits |= RIGHT_READ;
            if (mode & POSIX_OTH_W) effective_bits |= (RIGHT_WRITE | RIGHT_DELETE);
            if (mode & POSIX_OTH_X) effective_bits |= RIGHT_EXECUTE;
        }
    }

    char ebuf[128];
    rights_to_string(effective_bits, ebuf, sizeof(ebuf));

    if ((effective_bits & req_rights) == req_rights) {
        const char *which = (proc->uid == res->owner_uid) ? "owner"
                          : "group/other";
        snprintf(reason, reason_size,
                 "POSIX: %s bits grant [%s] -- GRANTED", which, ebuf);
        return 1;
    }

    char mbuf[128];
    rights_to_string(req_rights & ~effective_bits, mbuf, sizeof(mbuf));
    snprintf(reason, reason_size,
             "POSIX: effective bits [%s] insufficient, missing [%s] -- DENIED",
             ebuf, mbuf);
    return 0;
}

/* ================================================================
   COMBINED macOS ACCESS CHECK -- all three layers
   ================================================================ */
int macos_access_check(const Process *proc, const Resource *res,
                       int req_rights,
                       char *sandbox_reason, char *acl_reason,
                       char *posix_reason, int reason_size)
{
    if (!sandbox_check(proc, res, sandbox_reason, reason_size))
        return 0;

    int acl_result = acl_check(proc, res, req_rights, acl_reason, reason_size);
    if (acl_result == 1) return 1;
    if (acl_result == 0) return 0;

    return posix_check(proc, res, req_rights, posix_reason, reason_size);
}

void build_demo_world(void) {
    group_count = 0;
    user_count = 0;
    resource_count = 0;
    process_count = 0;

    groups[group_count++] = (Group){80,  "admin"};
    groups[group_count++] = (Group){20,  "staff"};
    groups[group_count++] = (Group){501, "developers"};
    groups[group_count++] = (Group){31,  "guest"};

    users[user_count] = (User){0, "root", .group_count = 1};
    users[user_count].group_ids[0] = 80;
    user_count++;

    users[user_count] = (User){501, "alice", .group_count = 2};
    users[user_count].group_ids[0] = 80;
    users[user_count].group_ids[1] = 20;
    user_count++;

    users[user_count] = (User){502, "bob", .group_count = 2};
    users[user_count].group_ids[0] = 20;
    users[user_count].group_ids[1] = 501;
    user_count++;

    users[user_count] = (User){503, "charlie", .group_count = 1};
    users[user_count].group_ids[0] = 31;
    user_count++;

    Resource *r1 = &resources[resource_count++];
    strcpy(r1->name, "/Users/alice/Documents/secrets.txt");
    r1->owner_uid = 501;
    r1->owner_gid = 20;
    r1->posix_mode = 0600;
    r1->acl.count = 0;
    strcpy(r1->category, "com.apple.files.documents");

    Resource *r2 = &resources[resource_count++];
    strcpy(r2->name, "/opt/project/src/main.c");
    r2->owner_uid = 502;
    r2->owner_gid = 501;
    r2->posix_mode = 0774;
    r2->acl.count = 2;
    r2->acl.entries[0] = (ACE){ACE_DENY,  31,  1, RIGHT_WRITE};
    r2->acl.entries[1] = (ACE){ACE_ALLOW, 501, 1, RIGHT_READ | RIGHT_WRITE};
    r2->category[0] = '\0';

    Resource *r3 = &resources[resource_count++];
    strcpy(r3->name, "/etc/sudoers");
    r3->owner_uid = 0;
    r3->owner_gid = 80;
    r3->posix_mode = 0440;
    r3->acl.count = 1;
    r3->acl.entries[0] = (ACE){ACE_ALLOW, 80, 1, RIGHT_READ};
    r3->category[0] = '\0';

    Resource *r4 = &resources[resource_count++];
    strcpy(r4->name, "/dev/camera0 (Camera)");
    r4->owner_uid = 0;
    r4->owner_gid = 80;
    r4->posix_mode = 0777;
    r4->acl.count = 0;
    strcpy(r4->category, "com.apple.security.device.camera");

    Process *p1 = &processes[process_count++];
    p1->pid = 100;  strcpy(p1->name, "Terminal.app");
    p1->uid = 501;
    p1->group_count = 2;
    p1->group_ids[0] = 80; p1->group_ids[1] = 20;
    p1->entitlement_count = 1;
    strcpy(p1->entitlements[0], "com.apple.files.documents");

    Process *p2 = &processes[process_count++];
    p2->pid = 200;  strcpy(p2->name, "VSCode");
    p2->uid = 502;
    p2->group_count = 2;
    p2->group_ids[0] = 20; p2->group_ids[1] = 501;
    p2->entitlement_count = 1;
    strcpy(p2->entitlements[0], "com.apple.files.documents");

    Process *p3 = &processes[process_count++];
    p3->pid = 300;  strcpy(p3->name, "Safari (guest)");
    p3->uid = 503;
    p3->group_count = 1;
    p3->group_ids[0] = 31;
    p3->entitlement_count = 0;

    Process *p4 = &processes[process_count++];
    p4->pid = 400;  strcpy(p4->name, "FaceTime.app");
    p4->uid = 501;
    p4->group_count = 2;
    p4->group_ids[0] = 80; p4->group_ids[1] = 20;
    p4->entitlement_count = 1;
    strcpy(p4->entitlements[0], "com.apple.security.device.camera");

    Process *p5 = &processes[process_count++];
    p5->pid = 500;  strcpy(p5->name, "sketchy_app");
    p5->uid = 502;
    p5->group_count = 2;
    p5->group_ids[0] = 20; p5->group_ids[1] = 501;
    p5->entitlement_count = 0;
}

void print_resource(const Resource *r) {
    char mbuf[16];
    mode_to_string(r->posix_mode, mbuf);
    printf("  Resource : \"%s\"\n", r->name);
    printf("    Owner  : %s (UID %d)  Group: %s (GID %d)\n",
           user_name(r->owner_uid), r->owner_uid,
           group_name(r->owner_gid), r->owner_gid);
    printf("    POSIX  : %s\n", mbuf);
    if (r->acl.count > 0) {
        printf("    ACL (%d entries):\n", r->acl.count);
        for (int i = 0; i < r->acl.count; i++) {
            const ACE *a = &r->acl.entries[i];
            char rbuf[128];
            rights_to_string(a->rights, rbuf, sizeof(rbuf));
            const char *who = a->is_group ? group_name(a->sid)
                                          : user_name(a->sid);
            printf("      ACE #%d: %-5s  %-16s  [%s]\n",
                   i + 1, a->type == ACE_DENY ? "DENY" : "ALLOW", who, rbuf);
        }
    } else {
        printf("    ACL    : (none)\n");
    }
    if (r->category[0])
        printf("    Sandbox: category \"%s\"\n", r->category);
    else
        printf("    Sandbox: (no category -- unrestricted)\n");
}

void print_process(const Process *p) {
    printf("  PID %d -- %s\n", p->pid, p->name);
    printf("    User   : %s (UID %d)\n", user_name(p->uid), p->uid);
    printf("    Groups : ");
    for (int i = 0; i < p->group_count; i++)
        printf("%s%s", group_name(p->group_ids[i]),
               i < p->group_count - 1 ? ", " : "");
    printf("\n");
    printf("    Entitlements: ");
    if (p->entitlement_count == 0) printf("(none)");
    for (int i = 0; i < p->entitlement_count; i++)
        printf("%s%s", p->entitlements[i],
               i < p->entitlement_count - 1 ? ", " : "");
    printf("\n");
}

void run_demo(void) {
    build_demo_world();

    printf("\n");
    print_separator();
    printf("  macOS SECURITY MODEL -- DEMO ENVIRONMENT\n");
    print_separator();

    printf("\n  USERS:\n");
    for (int i = 0; i < user_count; i++) {
        printf("    UID %-4d %-10s  Groups: ", users[i].uid, users[i].name);
        for (int j = 0; j < users[i].group_count; j++)
            printf("%s%s", group_name(users[i].group_ids[j]),
                   j < users[i].group_count - 1 ? ", " : "");
        printf("\n");
    }

    printf("\n  RESOURCES:\n");
    for (int i = 0; i < resource_count; i++) {
        print_resource(&resources[i]);
        printf("\n");
    }

    printf("  PROCESSES:\n");
    for (int i = 0; i < process_count; i++) {
        print_process(&processes[i]);
        printf("\n");
    }

    struct {
        int pid_idx;
        int res_idx;
        int requested_rights;
        const char *scenario;
    } tests[] = {
        {0, 0, RIGHT_READ,
         "Alice (owner) reads secrets.txt -- POSIX owner bits"},
        {1, 0, RIGHT_READ,
         "Bob reads Alice's secrets.txt -- POSIX denies 'other'"},
        {2, 0, RIGHT_READ,
         "Charlie (guest, no entitlement) reads secrets.txt -- SANDBOX blocks"},
        {1, 1, RIGHT_WRITE,
         "Bob (owner) writes main.c -- POSIX owner 'w' bit"},
        {0, 1, RIGHT_READ,
         "Alice reads main.c -- no ACL match, POSIX 'other' r bit"},
        {2, 1, RIGHT_WRITE,
         "Charlie (guest) writes main.c -- ACL DENY matches first"},
        {0, 2, RIGHT_READ,
         "Alice (admin group) reads /etc/sudoers -- ACL ALLOW admin"},
        {3, 3, RIGHT_READ,
         "FaceTime (has camera entitlement) accesses Camera -- SANDBOX pass"},
        {4, 3, RIGHT_READ,
         "sketchy_app (NO camera entitlement) accesses Camera -- SANDBOX blocks"},
    };

    int n_tests = sizeof(tests) / sizeof(tests[0]);

    printf("\n");
    print_separator();
    printf("  ACCESS CHECK SCENARIOS (three-layer evaluation)\n");
    print_separator();

    for (int t = 0; t < n_tests; t++) {
        Process  *p = &processes[tests[t].pid_idx];
        Resource *r = &resources[tests[t].res_idx];
        int       req = tests[t].requested_rights;
        char      rbuf[128];
        char      sandbox_reason[256] = "(not checked)";
        char      acl_reason[256]     = "(not checked)";
        char      posix_reason[256]   = "(not checked)";

        rights_to_string(req, rbuf, sizeof(rbuf));

        printf("\n  SCENARIO %d: %s\n", t + 1, tests[t].scenario);
        printf("    Process  : PID %d (%s) as %s\n", p->pid, p->name,
               user_name(p->uid));
        printf("    Resource : %s\n", r->name);
        printf("    Requested: [%s]\n", rbuf);

        int result = macos_access_check(p, r, req,
                                         sandbox_reason, acl_reason,
                                         posix_reason, sizeof(sandbox_reason));

        printf("    Layer 3 (Sandbox)  : %s\n", sandbox_reason);
        printf("    Layer 2 (ACL)      : %s\n", acl_reason);
        printf("    Layer 1 (POSIX)    : %s\n", posix_reason);
        printf("    [%s] FINAL RESULT: %s\n",
               result ? "GRANTED" : "DENIED",
               result ? "ACCESS GRANTED" : "ACCESS DENIED");
        print_separator();
    }
}

void interactive_mode(void) {
    build_demo_world();

    int choice = 0;
    while (1) {
        printf("\n");
        print_separator();
        printf("  INTERACTIVE MODE MENU\n");
        print_separator();
        printf("  1. List all users\n");
        printf("  2. List all resources (POSIX + ACL + Sandbox)\n");
        printf("  3. List all processes & entitlements\n");
        printf("  4. Perform an access check (all 3 layers)\n");
        printf("  5. Add ACE to a resource\n");
        printf("  6. Change a resource's POSIX mode\n");
        printf("  7. Return to main menu\n");
        printf("  Enter choice (1-7): ");

        int res = read_int_safe(&choice);
        if (res <= 0) {
            printf("\nExiting interactive mode.\n");
            break;
        }

        if (choice == 7) {
            break;
        }

        switch (choice) {
        case 1:
            printf("\n  USERS:\n");
            for (int i = 0; i < user_count; i++) {
                printf("    UID %-4d %-10s  Groups: ", users[i].uid, users[i].name);
                for (int j = 0; j < users[i].group_count; j++)
                    printf("%s%s", group_name(users[i].group_ids[j]),
                           j < users[i].group_count - 1 ? ", " : "");
                printf("\n");
            }
            break;

        case 2:
            printf("\n  RESOURCES:\n");
            for (int i = 0; i < resource_count; i++) {
                printf("  [%d] ", i);
                print_resource(&resources[i]);
                printf("\n");
            }
            break;

        case 3:
            printf("\n  PROCESSES:\n");
            for (int i = 0; i < process_count; i++) {
                printf("  [%d] ", i);
                print_process(&processes[i]);
            }
            break;

        case 4: {
            int pi, ri, rights;
            printf("  Enter process index (0-%d): ", process_count - 1);
            if (read_int_safe(&pi) <= 0 || pi < 0 || pi >= process_count) {
                printf("  Invalid process index.\n"); break;
            }
            printf("  Enter resource index (0-%d): ", resource_count - 1);
            if (read_int_safe(&ri) <= 0 || ri < 0 || ri >= resource_count) {
                printf("  Invalid resource index.\n"); break;
            }
            printf("  Enter rights bitmask (1=READ, 2=WRITE, 4=EXEC, 8=DELETE, sum): ");
            if (read_int_safe(&rights) <= 0) {
                printf("  Invalid rights.\n"); break;
            }

            char rbuf[128];
            char sr[256] = "(n/a)", ar[256] = "(n/a)", pr_str[256] = "(n/a)";
            rights_to_string(rights, rbuf, sizeof(rbuf));
            printf("    Checking: PID %d requests [%s] on \"%s\"\n",
                   processes[pi].pid, rbuf, resources[ri].name);

            int result = macos_access_check(&processes[pi], &resources[ri],
                                             rights, sr, ar, pr_str, sizeof(sr));
            printf("    Sandbox : %s\n", sr);
            printf("    ACL     : %s\n", ar);
            printf("    POSIX   : %s\n", pr_str);
            printf("    [%s] %s\n",
                   result ? "GRANTED" : "DENIED",
                   result ? "ACCESS GRANTED" : "ACCESS DENIED");
            break;
        }

        case 5: {
            int ri;
            printf("  Enter resource index (0-%d): ", resource_count - 1);
            if (read_int_safe(&ri) <= 0 || ri < 0 || ri >= resource_count) {
                printf("  Invalid resource index.\n"); break;
            }
            ACL *acl = &resources[ri].acl;
            if (acl->count >= MAX_ACES) { printf("  ACL full.\n"); break; }

            ACE *a = &acl->entries[acl->count];
            int tmp;
            printf("  Type (0=ALLOW, 1=DENY): ");
            if (read_int_safe(&tmp) <= 0) { printf("  Invalid.\n"); break; }
            a->type = tmp ? ACE_DENY : ACE_ALLOW;

            printf("  Is group? (0=user, 1=group): ");
            if (read_int_safe(&a->is_group) <= 0) { printf("  Invalid.\n"); break; }

            printf("  SID: ");
            if (read_int_safe(&a->sid) <= 0) { printf("  Invalid.\n"); break; }

            printf("  Rights bitmask (1=R, 2=W, 4=X, 8=D, sum): ");
            if (read_int_safe(&a->rights) <= 0) { printf("  Invalid.\n"); break; }

            acl->count++;
            printf("  ACE added successfully.\n");
            break;
        }

        case 6: {
            int ri, mode;
            printf("  Enter resource index (0-%d): ", resource_count - 1);
            if (read_int_safe(&ri) <= 0 || ri < 0 || ri >= resource_count) {
                printf("  Invalid resource index.\n"); break;
            }
            printf("  Enter new POSIX mode in octal (e.g. 755 or 644): ");
            if (read_octal_safe(&mode) <= 0) {
                printf("  Invalid octal mode.\n"); break;
            }
            resources[ri].posix_mode = mode;
            char mbuf[16];
            mode_to_string(mode, mbuf);
            printf("  Mode updated to %s (0%o)\n", mbuf, mode);
            break;
        }

        default:
            printf("  Unrecognized option. Please choose 1-7.\n");
            break;
        }
    }
}

int main(void) {
    int choice = 0;

    printf("+--------------------------------------------------------------+\n");
    printf("|   macOS SECURITY MODEL SIMULATION                            |\n");
    printf("|   POSIX Bits + ACLs + Sandbox Entitlements                   |\n");
    printf("+--------------------------------------------------------------+\n");
    printf("\n  1. Run PRESET DEMO (recommended -- 9 scenarios)\n");
    printf("  2. INTERACTIVE mode (inspect/modify then test)\n");
    printf("  Enter choice (1 or 2): ");

    int res = read_int_safe(&choice);
    if (res <= 0) {
        printf("\nExiting.\n");
        return 0;
    }

    if (choice == 2)
        interactive_mode();
    else
        run_demo();

    printf("\n  Simulation complete.\n");
    return 0;
}
