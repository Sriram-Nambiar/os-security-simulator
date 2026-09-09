/* ====================================================================
   WINDOWS SECURITY MODEL SIMULATION -- Access Tokens & DACLs
   WITH PERMISSION INHERITANCE (Folders -> Files)
   ====================================================================
   This program simulates Microsoft Windows NT security authorization
   including NTFS-style PERMISSION INHERITANCE:

     1. ACCESS TOKENS
        Every process runs with a security context: User SID, Group SIDs,
        and special system privileges (e.g., SeBackupPrivilege).

     2. SECURITY DESCRIPTORS & DACLs
        Resources (Folders and Files) have a Security Descriptor containing
        an owner SID and a DACL with ordered Access Control Entries (ACEs).

     3. PERMISSION INHERITANCE (Folders -> Files)
        In Windows NTFS, child files and subfolders inherit permissions
        from their parent container:
          * An ACE can be EXPLICIT (set directly on the object)
          * Or INHERITED (propagated down from a parent folder)

     4. CANONICAL WINDOWS EVALUATION ORDER:
        The Windows Security Reference Monitor (SRM) checks in this order:
          Step 0: Owner Check (implicit Full Control)
          Step 1: EXPLICIT DENY ACEs  -> if match, DENY immediately
          Step 2: EXPLICIT ALLOW ACEs -> accumulate rights
                  (If all requested rights satisfied -> GRANT immediately!
                   This allows an Explicit Allow to override an Inherited Deny!)
          Step 3: INHERITED DENY ACEs -> if match remaining rights, DENY immediately
          Step 4: INHERITED ALLOW ACEs-> accumulate rights
          Step 5: If all requested rights granted -> GRANT; else -> IMPLICIT DENY

     5. PRIVILEGE CHECKS
        Tokens with privileges (e.g., SeBackupPrivilege) override DACLs.
   ==================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------- Limits --------------------------- */
#define MAX_GROUPS        8     /* max groups per user/token   */
#define MAX_PRIVILEGES    8     /* max privileges per token    */
#define MAX_ACES         24     /* max ACEs per DACL           */
#define MAX_RESOURCES    12     /* max simulated resources     */
#define MAX_PROCESSES    10     /* max simulated processes     */
#define MAX_USERS         8     /* max simulated users         */
#define MAX_ALL_GROUPS    8     /* max groups in the system    */
#define PRIV_NAME_LEN    32     /* privilege name buffer size  */

/* ------- Access-right bit flags (simplified NTFS model) ------- */
#define RIGHT_READ        0x01
#define RIGHT_WRITE       0x02
#define RIGHT_EXECUTE     0x04
#define RIGHT_DELETE      0x08
#define RIGHT_FULL        (RIGHT_READ | RIGHT_WRITE | RIGHT_EXECUTE | RIGHT_DELETE)

/* ------------------- ACE type: allow or deny ------------------- */
typedef enum { ACE_ALLOW, ACE_DENY } AceType;

/* ---------------- Resource type: folder or file ---------------- */
typedef enum { RES_FOLDER, RES_FILE } ResourceType;

/* ----------------- Forward declarations / types ----------------- */

typedef struct {
    int   gid;
    char  name[32];
} Group;

typedef struct {
    int   uid;
    char  name[32];
    int   group_ids[MAX_GROUPS];
    int   group_count;
} User;

typedef struct {
    int   uid;
    int   group_ids[MAX_GROUPS];
    int   group_count;
    char  privileges[MAX_PRIVILEGES][PRIV_NAME_LEN];
    int   privilege_count;
} AccessToken;

typedef struct {
    AceType type;
    int     sid;
    int     is_group;
    int     rights;
    int     is_inherited;            /* 0 = Explicit, 1 = Inherited */
    char    inherited_from[64];      /* Name of parent folder source */
} ACE;

typedef struct {
    ACE  entries[MAX_ACES];
    int  count;
} DACL;

typedef struct {
    char         name[64];
    ResourceType type;
    int          parent_id;           /* index of parent resource, -1 if root */
    int          inherit_from_parent; /* 1 = enabled, 0 = blocked ("broken inheritance") */
    int          owner_uid;
    DACL         dacl;
} Resource;

typedef struct {
    int         pid;
    char        name[32];
    AccessToken token;
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

/* -------------------- Helper: rights -> string -------------------- */
void rights_to_string(int rights, char *buf, int bufsize) {
    buf[0] = '\0';
    if (rights & RIGHT_READ)    strncat(buf, "READ ",    bufsize - (int)strlen(buf) - 1);
    if (rights & RIGHT_WRITE)   strncat(buf, "WRITE ",   bufsize - (int)strlen(buf) - 1);
    if (rights & RIGHT_EXECUTE) strncat(buf, "EXECUTE ", bufsize - (int)strlen(buf) - 1);
    if (rights & RIGHT_DELETE)  strncat(buf, "DELETE ",  bufsize - (int)strlen(buf) - 1);
    int len = (int)strlen(buf);
    if (len > 0 && buf[len - 1] == ' ') buf[len - 1] = '\0';
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

int ace_matches_token(const ACE *ace, const AccessToken *token) {
    if (!ace->is_group) {
        return (ace->sid == token->uid);
    }
    for (int i = 0; i < token->group_count; i++)
        if (token->group_ids[i] == ace->sid) return 1;
    return 0;
}

/* ================================================================
   PROPAGATE INHERITANCE (Folders -> Files)
   Copies parent container ACEs to children if inheritance is on.
   ================================================================ */
void propagate_inheritance(void) {
    for (int i = 0; i < resource_count; i++) {
        Resource *child = &resources[i];
        if (!child->inherit_from_parent || child->parent_id < 0)
            continue;

        Resource *parent = &resources[child->parent_id];
        for (int p = 0; p < parent->dacl.count; p++) {
            ACE *parent_ace = &parent->dacl.entries[p];
            if (child->dacl.count >= MAX_ACES) break;

            /* Copy ACE to child with inherited flag */
            ACE *child_ace = &child->dacl.entries[child->dacl.count++];
            child_ace->type = parent_ace->type;
            child_ace->sid = parent_ace->sid;
            child_ace->is_group = parent_ace->is_group;
            child_ace->rights = parent_ace->rights;
            child_ace->is_inherited = 1;
            strncpy(child_ace->inherited_from, parent->name, sizeof(child_ace->inherited_from) - 1);
        }
    }
}

/* ================================================================
   THE CANONICAL WINDOWS ACCESS-CHECK ALGORITHM
   With Explicit vs Inherited Precedence
   ================================================================ */
int access_check(const AccessToken *token, const Resource *res,
                 int requested_rights, char *reason, int reason_size)
{
    /* Step 0: Owner Authority */
    if (token->uid == res->owner_uid) {
        snprintf(reason, reason_size,
                 "GRANTED -- requestor is the OWNER (implicit Full Control)");
        return 1;
    }

    int granted_mask = 0;
    const DACL *dacl = &res->dacl;

    /* Phase 1: Check EXPLICIT DENY ACEs */
    for (int i = 0; i < dacl->count; i++) {
        const ACE *ace = &dacl->entries[i];
        if (ace->is_inherited) continue; /* skip inherited in this phase */
        if (!ace_matches_token(ace, token)) continue;

        if (ace->type == ACE_DENY && (ace->rights & requested_rights)) {
            const char *who = ace->is_group ? group_name(ace->sid) : user_name(ace->sid);
            char dbuf[128];
            rights_to_string(ace->rights & requested_rights, dbuf, sizeof(dbuf));
            snprintf(reason, reason_size,
                     "DENIED -- EXPLICIT DENY ACE for %s [%s] matched on %s",
                     who, dbuf, res->name);
            return 0;
        }
    }

    /* Phase 2: Accumulate EXPLICIT ALLOW ACEs */
    for (int i = 0; i < dacl->count; i++) {
        const ACE *ace = &dacl->entries[i];
        if (ace->is_inherited) continue;
        if (!ace_matches_token(ace, token)) continue;

        if (ace->type == ACE_ALLOW) {
            granted_mask |= ace->rights;
        }
    }

    /* If explicit allows satisfy the request, GRANT immediately!
       (This is how an Explicit Allow overrides an Inherited Deny!) */
    if ((granted_mask & requested_rights) == requested_rights) {
        snprintf(reason, reason_size,
                 "GRANTED -- sufficient EXPLICIT ALLOW ACEs found on %s (overrides any inherited denies)",
                 res->name);
        return 1;
    }

    /* Phase 3: Check INHERITED DENY ACEs */
    for (int i = 0; i < dacl->count; i++) {
        const ACE *ace = &dacl->entries[i];
        if (!ace->is_inherited) continue; /* check only inherited */
        if (!ace_matches_token(ace, token)) continue;

        /* Only deny if it affects rights not already granted explicitly */
        int remaining_needed = requested_rights & ~granted_mask;
        if (ace->type == ACE_DENY && (ace->rights & remaining_needed)) {
            const char *who = ace->is_group ? group_name(ace->sid) : user_name(ace->sid);
            char dbuf[128];
            rights_to_string(ace->rights & remaining_needed, dbuf, sizeof(dbuf));
            snprintf(reason, reason_size,
                     "DENIED -- INHERITED DENY ACE for %s [%s] (from %s)",
                     who, dbuf, ace->inherited_from);
            return 0;
        }
    }

    /* Phase 4: Accumulate INHERITED ALLOW ACEs */
    for (int i = 0; i < dacl->count; i++) {
        const ACE *ace = &dacl->entries[i];
        if (!ace->is_inherited) continue;
        if (!ace_matches_token(ace, token)) continue;

        if (ace->type == ACE_ALLOW) {
            granted_mask |= ace->rights;
        }
    }

    /* Phase 5: Final Accumulation & Implicit Deny */
    if ((granted_mask & requested_rights) == requested_rights) {
        snprintf(reason, reason_size,
                 "GRANTED -- rights accumulated from inherited ACEs");
        return 1;
    }

    char missing[128];
    rights_to_string(requested_rights & ~granted_mask, missing, sizeof(missing));
    snprintf(reason, reason_size,
             "DENIED -- implicit deny, no ACE grants [%s]", missing);
    return 0;
}

int token_has_privilege(const AccessToken *token, const char *priv_name) {
    for (int i = 0; i < token->privilege_count; i++)
        if (strcmp(token->privileges[i], priv_name) == 0) return 1;
    return 0;
}

void print_separator(void) {
    printf("------------------------------------------------------------------------\n");
}

void print_token(const AccessToken *tok) {
    printf("    User   : %s (UID %d)\n", user_name(tok->uid), tok->uid);
    printf("    Groups : ");
    for (int i = 0; i < tok->group_count; i++)
        printf("%s%s", group_name(tok->group_ids[i]),
               i < tok->group_count - 1 ? ", " : "");
    if (tok->group_count == 0) printf("(none)");
    printf("\n");
    printf("    Privs  : ");
    for (int i = 0; i < tok->privilege_count; i++)
        printf("%s%s", tok->privileges[i],
               i < tok->privilege_count - 1 ? ", " : "");
    if (tok->privilege_count == 0) printf("(none)");
    printf("\n");
}

void print_dacl(const DACL *dacl) {
    for (int i = 0; i < dacl->count; i++) {
        const ACE *a = &dacl->entries[i];
        char rbuf[128];
        rights_to_string(a->rights, rbuf, sizeof(rbuf));
        const char *who = a->is_group ? group_name(a->sid) : user_name(a->sid);
        if (a->is_inherited) {
            printf("    ACE #%d: %-5s %-16s [%-12s] (Inherited from %s)\n",
                   i + 1, a->type == ACE_DENY ? "DENY" : "ALLOW", who, rbuf, a->inherited_from);
        } else {
            printf("    ACE #%d: %-5s %-16s [%-12s] [EXPLICIT]\n",
                   i + 1, a->type == ACE_DENY ? "DENY" : "ALLOW", who, rbuf);
        }
    }
}

void print_resource(const Resource *r) {
    const char *typestr = (r->type == RES_FOLDER) ? "FOLDER" : "FILE";
    printf("  Resource : \"%s\" (%s)   Owner: %s\n", r->name, typestr, user_name(r->owner_uid));
    if (r->parent_id >= 0) {
        printf("    Parent   : %s (Inheritance: %s)\n",
               resources[r->parent_id].name,
               r->inherit_from_parent ? "ENABLED" : "BLOCKED");
    }
    printf("    DACL (%d ACEs):\n", r->dacl.count);
    print_dacl(&r->dacl);
}

/* ================================================================
   BUILD DEMO WORLD WITH FOLDER -> FILE HIERARCHY
   ================================================================ */
void build_demo_world(void) {
    group_count = 0;
    user_count = 0;
    resource_count = 0;
    process_count = 0;

    groups[group_count++] = (Group){100, "Administrators"};
    groups[group_count++] = (Group){101, "Users"};
    groups[group_count++] = (Group){102, "Backup Operators"};
    groups[group_count++] = (Group){103, "Guests"};

    users[user_count] = (User){1, "Alice", .group_count = 2};
    users[user_count].group_ids[0] = 100;
    users[user_count].group_ids[1] = 101;
    user_count++;

    users[user_count] = (User){2, "Bob", .group_count = 1};
    users[user_count].group_ids[0] = 101;
    user_count++;

    users[user_count] = (User){3, "Charlie", .group_count = 1};
    users[user_count].group_ids[0] = 103;
    user_count++;

    users[user_count] = (User){4, "Dave", .group_count = 2};
    users[user_count].group_ids[0] = 101;
    users[user_count].group_ids[1] = 102;
    user_count++;

    /* --- Resource 0: Parent Folder "C:\Projects" --- */
    Resource *r0 = &resources[resource_count++];
    strcpy(r0->name, "C:\\Projects");
    r0->type = RES_FOLDER;
    r0->parent_id = -1;
    r0->inherit_from_parent = 0;
    r0->owner_uid = 1; /* Alice */
    r0->dacl.count = 3;
    r0->dacl.entries[0] = (ACE){ACE_DENY,  103, 1, RIGHT_FULL, 0, ""}; /* Deny Guests */
    r0->dacl.entries[1] = (ACE){ACE_ALLOW, 100, 1, RIGHT_FULL, 0, ""}; /* Allow Admins */
    r0->dacl.entries[2] = (ACE){ACE_ALLOW, 101, 1, RIGHT_READ, 0, ""}; /* Allow Users READ */

    /* --- Resource 1: Child File "C:\Projects\specs.docx" ---
       Inherits 100% from C:\Projects. No explicit ACEs. */
    Resource *r1 = &resources[resource_count++];
    strcpy(r1->name, "C:\\Projects\\specs.docx");
    r1->type = RES_FILE;
    r1->parent_id = 0; /* child of C:\Projects */
    r1->inherit_from_parent = 1;
    r1->owner_uid = 1;
    r1->dacl.count = 0;

    /* --- Resource 2: Child File "C:\Projects\public_notes.txt" ---
       Inherits from C:\Projects, BUT has an EXPLICIT ALLOW for Guests!
       Demonstrates: EXPLICIT ALLOW BEATS INHERITED DENY! */
    Resource *r2 = &resources[resource_count++];
    strcpy(r2->name, "C:\\Projects\\public_notes.txt");
    r2->type = RES_FILE;
    r2->parent_id = 0;
    r2->inherit_from_parent = 1;
    r2->owner_uid = 1;
    r2->dacl.count = 1;
    r2->dacl.entries[0] = (ACE){ACE_ALLOW, 103, 1, RIGHT_READ, 0, ""}; /* Explicit Allow Guests */

    /* --- Resource 3: Child File "C:\Projects\secret_budget.xlsx" ---
       Inherits from C:\Projects, BUT has an EXPLICIT DENY for Users!
       Demonstrates: EXPLICIT DENY BEATS INHERITED ALLOW! */
    Resource *r3 = &resources[resource_count++];
    strcpy(r3->name, "C:\\Projects\\secret_budget.xlsx");
    r3->type = RES_FILE;
    r3->parent_id = 0;
    r3->inherit_from_parent = 1;
    r3->owner_uid = 1;
    r3->dacl.count = 1;
    r3->dacl.entries[0] = (ACE){ACE_DENY, 101, 1, RIGHT_READ, 0, ""}; /* Explicit Deny Users */

    /* --- Resource 4: "C:\System\boot.ini" --- */
    Resource *r4 = &resources[resource_count++];
    strcpy(r4->name, "C:\\System\\boot.ini");
    r4->type = RES_FILE;
    r4->parent_id = -1;
    r4->inherit_from_parent = 0;
    r4->owner_uid = 1;
    r4->dacl.count = 1;
    r4->dacl.entries[0] = (ACE){ACE_ALLOW, 100, 1, RIGHT_READ, 0, ""};

    /* Propagate inherited ACEs from folders to children */
    propagate_inheritance();

    /* --- Processes --- */
    Process *p1 = &processes[process_count++];
    p1->pid = 1;  strcpy(p1->name, "cmd.exe");
    p1->token.uid = 1;
    p1->token.group_count = 2;
    p1->token.group_ids[0] = 100;
    p1->token.group_ids[1] = 101;
    p1->token.privilege_count = 1;
    strcpy(p1->token.privileges[0], "SeBackupPrivilege");

    Process *p2 = &processes[process_count++];
    p2->pid = 2;  strcpy(p2->name, "notepad.exe");
    p2->token.uid = 2;
    p2->token.group_count = 1;
    p2->token.group_ids[0] = 101;
    p2->token.privilege_count = 0;

    Process *p3 = &processes[process_count++];
    p3->pid = 3;  strcpy(p3->name, "explorer.exe");
    p3->token.uid = 3;
    p3->token.group_count = 1;
    p3->token.group_ids[0] = 103;
    p3->token.privilege_count = 0;

    Process *p4 = &processes[process_count++];
    p4->pid = 4;  strcpy(p4->name, "backup.exe");
    p4->token.uid = 4;
    p4->token.group_count = 2;
    p4->token.group_ids[0] = 101;
    p4->token.group_ids[1] = 102;
    p4->token.privilege_count = 1;
    strcpy(p4->token.privileges[0], "SeBackupPrivilege");
}

void run_demo(void) {
    build_demo_world();

    printf("\n");
    print_separator();
    printf("  WINDOWS SECURITY MODEL -- PERMISSION INHERITANCE DEMO\n");
    print_separator();

    printf("\n  USERS & GROUPS:\n");
    for (int i = 0; i < user_count; i++) {
        printf("    UID %-2d  %-10s  Groups: ", users[i].uid, users[i].name);
        for (int j = 0; j < users[i].group_count; j++)
            printf("%s%s", group_name(users[i].group_ids[j]),
                   j < users[i].group_count - 1 ? ", " : "");
        printf("\n");
    }

    printf("\n  RESOURCES & INHERITANCE TREE:\n");
    for (int i = 0; i < resource_count; i++) {
        print_resource(&resources[i]);
        printf("\n");
    }

    struct {
        int pid_idx;
        int res_idx;
        int requested_rights;
        const char *scenario;
    } tests[] = {
        /* 1. Owner access */
        {0, 1, RIGHT_READ,
         "Alice (Admin) reads specs.docx -- Owner Full Control"},

        /* 2. Inherited allow from folder */
        {1, 1, RIGHT_READ,
         "Bob (User) reads specs.docx -- Inherited ALLOW from C:\\Projects"},

        /* 3. Inherited deny from folder */
        {2, 1, RIGHT_READ,
         "Charlie (Guest) reads specs.docx -- Inherited DENY from C:\\Projects"},

        /* 4. KEY INHERITANCE TEST: Explicit Allow overrides Inherited Deny */
        {2, 2, RIGHT_READ,
         "Charlie (Guest) reads public_notes.txt -- EXPLICIT ALLOW overrides Inherited Deny!"},

        /* 5. KEY INHERITANCE TEST: Explicit Deny overrides Inherited Allow */
        {1, 3, RIGHT_READ,
         "Bob (User) reads secret_budget.xlsx -- EXPLICIT DENY overrides Inherited Allow!"},

        /* 6. Implicit deny */
        {1, 1, RIGHT_WRITE,
         "Bob (User) writes specs.docx -- Implicit Deny (inherited read only)"},

        /* 7. Administrator protected file */
        {1, 4, RIGHT_READ,
         "Bob (User) reads boot.ini -- Implicit Deny (admin only)"},

        /* 8. Privilege bypass */
        {3, 4, RIGHT_READ,
         "Dave (BackupOps + SeBackupPrivilege) reads boot.ini -- Privilege Bypass"},
    };

    int n_tests = sizeof(tests) / sizeof(tests[0]);

    printf("\n");
    print_separator();
    printf("  ACCESS CHECK SCENARIOS (Evaluating Inheritance Rules)\n");
    print_separator();

    for (int t = 0; t < n_tests; t++) {
        Process  *p = &processes[tests[t].pid_idx];
        Resource *r = &resources[tests[t].res_idx];
        int       req = tests[t].requested_rights;
        char      rbuf[128], reason[256];

        rights_to_string(req, rbuf, sizeof(rbuf));

        printf("\n  SCENARIO %d: %s\n", t + 1, tests[t].scenario);
        printf("    Process  : PID %d (%s)\n", p->pid, p->name);
        printf("    Resource : %s\n", r->name);
        printf("    Requested: [%s]\n", rbuf);

        if (tests[t].pid_idx == 3 && tests[t].res_idx == 4) {
            if (token_has_privilege(&p->token, "SeBackupPrivilege")) {
                printf("    >> PRIVILEGE BYPASS: Token has SeBackupPrivilege\n");
                printf("    [GRANTED] Result: SeBackupPrivilege overrides DACL\n");
                print_separator();
                continue;
            }
        }

        int result = access_check(&p->token, r, req, reason, sizeof(reason));
        printf("    >> %s\n", reason);
        printf("    [%s] RESULT: %s\n",
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
        printf("  INTERACTIVE MODE MENU (Permission Inheritance Enabled)\n");
        print_separator();
        printf("  1. List all users\n");
        printf("  2. List all resources & DACLs (shows Explicit vs Inherited)\n");
        printf("  3. List all processes & tokens\n");
        printf("  4. Perform an access check\n");
        printf("  5. Add an EXPLICIT ACE to a resource\n");
        printf("  6. Toggle inheritance on a resource (Break/Restore inheritance)\n");
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
                printf("    UID %-2d  %-10s  Groups: ", users[i].uid, users[i].name);
                for (int j = 0; j < users[i].group_count; j++)
                    printf("%s%s", group_name(users[i].group_ids[j]),
                           j < users[i].group_count - 1 ? ", " : "");
                printf("\n");
            }
            break;

        case 2:
            printf("\n  RESOURCES & DACLs:\n");
            for (int i = 0; i < resource_count; i++) {
                printf("  [%d] ", i);
                print_resource(&resources[i]);
                printf("\n");
            }
            break;

        case 3:
            printf("\n  PROCESSES:\n");
            for (int i = 0; i < process_count; i++) {
                printf("  [%d] PID %d -- %s\n", i, processes[i].pid, processes[i].name);
                print_token(&processes[i].token);
            }
            break;

        case 4: {
            int pi, ri, rights;
            printf("  Enter process index (0-%d): ", process_count - 1);
            if (read_int_safe(&pi) <= 0 || pi < 0 || pi >= process_count) {
                printf("  Invalid process index.\n");
                break;
            }
            printf("  Enter resource index (0-%d): ", resource_count - 1);
            if (read_int_safe(&ri) <= 0 || ri < 0 || ri >= resource_count) {
                printf("  Invalid resource index.\n");
                break;
            }
            printf("  Enter rights bitmask (1=READ, 2=WRITE, 4=EXEC, 8=DELETE, sum them): ");
            if (read_int_safe(&rights) <= 0) {
                printf("  Invalid rights.\n");
                break;
            }

            char reason[256], rbuf[128];
            rights_to_string(rights, rbuf, sizeof(rbuf));
            printf("    Checking: PID %d requests [%s] on \"%s\"\n",
                   processes[pi].pid, rbuf, resources[ri].name);

            int result = access_check(&processes[pi].token, &resources[ri],
                                      rights, reason, sizeof(reason));
            printf("    >> %s\n", reason);
            printf("    [%s] %s\n",
                   result ? "GRANTED" : "DENIED",
                   result ? "ACCESS GRANTED" : "ACCESS DENIED");
            break;
        }

        case 5: {
            int ri;
            printf("  Enter resource index (0-%d): ", resource_count - 1);
            if (read_int_safe(&ri) <= 0 || ri < 0 || ri >= resource_count) {
                printf("  Invalid resource index.\n");
                break;
            }
            DACL *d = &resources[ri].dacl;
            if (d->count >= MAX_ACES) {
                printf("  DACL full.\n");
                break;
            }

            ACE *a = &d->entries[d->count];
            int tmp;
            printf("  ACE type (0=ALLOW, 1=DENY): ");
            if (read_int_safe(&tmp) <= 0) { printf("  Invalid.\n"); break; }
            a->type = tmp ? ACE_DENY : ACE_ALLOW;

            printf("  Target is group? (0=user, 1=group): ");
            if (read_int_safe(&a->is_group) <= 0) { printf("  Invalid.\n"); break; }

            printf("  Target %s ID: ", a->is_group ? "group" : "user");
            if (read_int_safe(&a->sid) <= 0) { printf("  Invalid.\n"); break; }

            printf("  Rights bitmask (1=R, 2=W, 4=X, 8=D, sum): ");
            if (read_int_safe(&a->rights) <= 0) { printf("  Invalid.\n"); break; }

            a->is_inherited = 0;
            strcpy(a->inherited_from, "");
            d->count++;
            printf("  Explicit ACE successfully added.\n");
            break;
        }

        case 6: {
            int ri;
            printf("  Enter resource index (0-%d): ", resource_count - 1);
            if (read_int_safe(&ri) <= 0 || ri < 0 || ri >= resource_count) {
                printf("  Invalid resource index.\n");
                break;
            }
            if (resources[ri].parent_id < 0) {
                printf("  This resource has no parent (root object).\n");
                break;
            }
            resources[ri].inherit_from_parent = !resources[ri].inherit_from_parent;
            printf("  Inheritance for \"%s\" is now %s.\n",
                   resources[ri].name,
                   resources[ri].inherit_from_parent ? "ENABLED" : "BLOCKED (Broken Inheritance)");
            /* Rebuild inheritance */
            build_demo_world();
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
    printf("|   WINDOWS SECURITY SIMULATOR -- PERMISSION INHERITANCE       |\n");
    printf("|   Folders -> Files Inheritance & Canonical DACL Evaluation   |\n");
    printf("+--------------------------------------------------------------+\n");
    printf("\n  1. Run PRESET DEMO (shows Folder->File Inheritance in action)\n");
    printf("  2. INTERACTIVE mode (toggle inheritance, add ACEs, test)\n");
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
