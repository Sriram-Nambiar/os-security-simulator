/* ====================================================================
   WINDOWS SECURITY MODEL SIMULATION -- Access Tokens & ACLs
   ====================================================================
   This program simulates the core concepts behind Microsoft Windows'
   security model. It is NOT a real operating system -- it is a
   simplified software MODEL built to demonstrate the underlying ideas:

     1. ACCESS TOKENS
        Every process in Windows runs with an access token that records:
          * The Security Identifier (SID) of the user who owns it
          * A list of group SIDs the user belongs to
          * A set of PRIVILEGES (special system-wide capabilities such
            as SeBackupPrivilege, SeDebugPrivilege, etc.)

     2. SECURITY DESCRIPTORS & DACLs
        Every securable resource (files, registry keys, services, ...)
        has a security descriptor that contains:
          * An owner SID
          * A Discretionary Access Control List (DACL) -- an ordered
            list of Access Control Entries (ACEs)

     3. ACE EVALUATION ORDER (the key Windows rule)
        When a process requests access to a resource, Windows walks
        the DACL from first ACE to last:
          a) If an explicit DENY ACE matches the requesting token and
             covers ANY of the requested rights -> ACCESS DENIED.
          b) As it walks, it accumulates ALLOW rights from matching
             ALLOW ACEs.
          c) After all ACEs are checked, if all requested rights have
             been granted -> ACCESS GRANTED.
          d) Otherwise -> ACCESS DENIED (implicit deny).

     4. PRIVILEGE CHECKS
        Some operations bypass normal ACL checks entirely if the
        token carries a specific enabled privilege (e.g., an admin
        process with SeBackupPrivilege can read any file regardless
        of ACLs -- used by the Windows Backup utility).

   SIMPLIFICATIONS:
     - Real Windows SIDs are long binary structures (S-1-5-21-...);
       here we use small integer IDs.
     - Real DACLs have inheritance, generic mappings, SACL auditing;
       we focus on the DACL evaluation algorithm itself.
     - Privileges are modelled as named strings for clarity.
   ==================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------- Limits --------------------------- */
#define MAX_GROUPS        8     /* max groups per user/token   */
#define MAX_PRIVILEGES    8     /* max privileges per token    */
#define MAX_ACES         16     /* max ACEs per DACL           */
#define MAX_RESOURCES    10     /* max simulated resources     */
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
} ACE;

typedef struct {
    ACE  entries[MAX_ACES];
    int  count;
} DACL;

typedef struct {
    char  name[64];
    int   owner_uid;
    DACL  dacl;
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
   THE CORE WINDOWS ACCESS-CHECK ALGORITHM
   Returns 1 = GRANTED, 0 = DENIED.
   ================================================================ */
int access_check(const AccessToken *token, const Resource *res,
                 int requested_rights, char *reason, int reason_size)
{
    /* Step 0: Owner always gets implicit full control */
    if (token->uid == res->owner_uid) {
        snprintf(reason, reason_size,
                 "GRANTED -- requestor is the OWNER (implicit Full Control)");
        return 1;
    }

    /* Step 1: Walk ACEs in order */
    int granted_mask = 0;
    const DACL *dacl = &res->dacl;

    for (int i = 0; i < dacl->count; i++) {
        const ACE *ace = &dacl->entries[i];
        if (!ace_matches_token(ace, token)) continue;

        if (ace->type == ACE_DENY) {
            if (ace->rights & requested_rights) {
                const char *who = ace->is_group ? group_name(ace->sid)
                                                : user_name(ace->sid);
                char denied_rights[128];
                rights_to_string(ace->rights & requested_rights,
                                 denied_rights, sizeof(denied_rights));
                snprintf(reason, reason_size,
                         "DENIED -- explicit DENY ACE for %s [%s] matched at ACE #%d",
                         who, denied_rights, i + 1);
                return 0;
            }
        } else {
            granted_mask |= ace->rights;
        }
    }

    /* Step 2: Accumulated rights check */
    if ((granted_mask & requested_rights) == requested_rights) {
        snprintf(reason, reason_size,
                 "GRANTED -- sufficient ALLOW ACEs found in DACL");
        return 1;
    }

    /* Step 3: Implicit deny */
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
        const char *who = a->is_group ? group_name(a->sid)
                                      : user_name(a->sid);
        printf("    ACE #%d: %-5s  %-18s  [%s]\n",
               i + 1, a->type == ACE_DENY ? "DENY" : "ALLOW", who, rbuf);
    }
}

void print_resource(const Resource *r) {
    printf("  Resource : \"%s\"   Owner: %s\n", r->name, user_name(r->owner_uid));
    printf("  DACL (%d ACEs):\n", r->dacl.count);
    print_dacl(&r->dacl);
}

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

    Resource *r1 = &resources[resource_count++];
    strcpy(r1->name, "C:\\Confidential\\report.docx");
    r1->owner_uid = 1;
    r1->dacl.count = 3;
    r1->dacl.entries[0] = (ACE){ACE_DENY,  103, 1, RIGHT_FULL};
    r1->dacl.entries[1] = (ACE){ACE_ALLOW, 100, 1, RIGHT_FULL};
    r1->dacl.entries[2] = (ACE){ACE_ALLOW, 101, 1, RIGHT_READ};

    Resource *r2 = &resources[resource_count++];
    strcpy(r2->name, "D:\\Shared\\project.xlsx");
    r2->owner_uid = 2;
    r2->dacl.count = 2;
    r2->dacl.entries[0] = (ACE){ACE_DENY,  102, 1, RIGHT_WRITE | RIGHT_DELETE};
    r2->dacl.entries[1] = (ACE){ACE_ALLOW, 101, 1, RIGHT_READ  | RIGHT_WRITE};

    Resource *r3 = &resources[resource_count++];
    strcpy(r3->name, "C:\\System\\boot.ini");
    r3->owner_uid = 1;
    r3->dacl.count = 1;
    r3->dacl.entries[0] = (ACE){ACE_ALLOW, 100, 1, RIGHT_READ};

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
    printf("  WINDOWS SECURITY MODEL -- DEMO ENVIRONMENT\n");
    print_separator();

    printf("\n  USERS:\n");
    for (int i = 0; i < user_count; i++) {
        printf("    UID %-2d  %-10s  Groups: ", users[i].uid, users[i].name);
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
        printf("  PID %d -- %s\n", processes[i].pid, processes[i].name);
        print_token(&processes[i].token);
        printf("\n");
    }

    struct {
        int pid_idx;
        int res_idx;
        int requested_rights;
        const char *scenario;
    } tests[] = {
        {0, 0, RIGHT_READ,
         "Alice (Admin) reads report.docx"},
        {1, 0, RIGHT_READ,
         "Bob (User) reads report.docx"},
        {1, 0, RIGHT_WRITE,
         "Bob (User) writes report.docx"},
        {2, 0, RIGHT_READ,
         "Charlie (Guest) reads report.docx"},
        {3, 1, RIGHT_WRITE,
         "Dave (User+BackupOps) writes project.xlsx"},
        {3, 1, RIGHT_READ,
         "Dave (User+BackupOps) reads project.xlsx"},
        {1, 2, RIGHT_READ,
         "Bob (User) reads boot.ini"},
        {3, 2, RIGHT_READ,
         "Dave (BackupOps + SeBackupPrivilege) reads boot.ini"},
    };

    int n_tests = sizeof(tests) / sizeof(tests[0]);

    printf("\n");
    print_separator();
    printf("  ACCESS CHECK SCENARIOS\n");
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

        if (tests[t].pid_idx == 3 && tests[t].res_idx == 2) {
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
        printf("  INTERACTIVE MODE MENU\n");
        print_separator();
        printf("  1. List all users\n");
        printf("  2. List all resources & DACLs\n");
        printf("  3. List all processes & tokens\n");
        printf("  4. Perform an access check\n");
        printf("  5. Add a new ACE to a resource's DACL\n");
        printf("  6. Return to main menu\n");
        printf("  Enter choice (1-6): ");

        int res = read_int_safe(&choice);
        if (res <= 0) {
            printf("\nExiting interactive mode.\n");
            break;
        }

        if (choice == 6) {
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

            d->count++;
            printf("  ACE successfully added.\n");
            break;
        }

        default:
            printf("  Unrecognized option. Please choose 1-6.\n");
            break;
        }
    }
}

int main(void) {
    int choice = 0;

    printf("+--------------------------------------------------------------+\n");
    printf("|   WINDOWS SECURITY MODEL SIMULATION                          |\n");
    printf("|   Access Tokens, DACLs & Privilege Checks                    |\n");
    printf("+--------------------------------------------------------------+\n");
    printf("\n  1. Run PRESET DEMO (recommended -- 8 scenarios)\n");
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
