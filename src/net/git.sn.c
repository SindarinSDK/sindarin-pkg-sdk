/* ==============================================================================
 * sdk/net/git.sn.c - Git Repository Implementation
 * ==============================================================================
 * This file provides the C implementation for Git repository operations using
 * libgit2. It is compiled via @source and linked with Sindarin code.
 *
 * Authentication:
 *   SSH:   SN_GIT_SSH_KEY, SN_GIT_SSH_PASSPHRASE (fallback to ssh-agent)
 *   HTTPS: SN_GIT_USERNAME, SN_GIT_PASSWORD / SN_GIT_TOKEN
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* No arena runtime — minimal runtime */

/* libgit2 includes */
#include <git2.h>

/* Platform-specific includes */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <direct.h>
    #ifndef PATH_MAX
        #define PATH_MAX 260
    #endif
#else
    #include <unistd.h>
    #include <limits.h>
#endif

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef __sn__GitRepo RtGitRepo;
typedef __sn__GitCommit RtGitCommit;
typedef __sn__GitBranch RtGitBranch;
typedef __sn__GitRemote RtGitRemote;
typedef __sn__GitDiff RtGitDiff;
typedef __sn__GitStatus RtGitStatus;
typedef __sn__GitTag RtGitTag;

/* Cast macros for repo_ptr stored as long to avoid auto-cleanup freeing it */
#define REPO_PTR(s) ((git_repository*)(uintptr_t)(s)->repo_ptr)
#define SET_REPO_PTR(s, v) ((s)->repo_ptr = (long long)(uintptr_t)(v))

/* ============================================================================
 * libgit2 Initialization (one-time)
 * ============================================================================ */

static int libgit2_initialized = 0;

static void ensure_libgit2_initialized(void) {
    if (!libgit2_initialized) {
        git_libgit2_init();
        libgit2_initialized = 1;
    }
}

/* ============================================================================
 * Credential Callback for Network Operations
 * ============================================================================ */

static int cred_attempt_count = 0;

static int git_credential_cb(git_credential **out, const char *url,
                              const char *username_from_url,
                              unsigned int allowed_types, void *payload) {
    (void)payload;
    (void)url;

    /* Prevent infinite retry loops */
    cred_attempt_count++;
    if (cred_attempt_count > 3) {
        return GIT_EAUTH;
    }

    const char *user = username_from_url;
    if (!user) user = getenv("SN_GIT_USERNAME");
    if (!user) user = "git"; /* Default for SSH */

    /* Try SSH key authentication */
    if (allowed_types & GIT_CREDENTIAL_SSH_KEY) {
        const char *key_path = getenv("SN_GIT_SSH_KEY");
        const char *passphrase = getenv("SN_GIT_SSH_PASSPHRASE");

        if (key_path) {
            return git_credential_ssh_key_new(out, user, NULL, key_path,
                                              passphrase ? passphrase : "");
        }
        /* Try SSH agent */
        return git_credential_ssh_key_from_agent(out, user);
    }

    /* Userpass for HTTPS */
    if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
        const char *username = getenv("SN_GIT_USERNAME");
        const char *password = getenv("SN_GIT_PASSWORD");
        if (!password) password = getenv("SN_GIT_TOKEN");

        if (username && password) {
            return git_credential_userpass_plaintext_new(out, username, password);
        }
    }

    return GIT_EAUTH;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static char *arena_strdup_local(const char *str) {
    if (!str) return strdup("");
    return strdup(str);
}

static const char *diff_status_to_string(git_delta_t status) {
    switch (status) {
        case GIT_DELTA_ADDED:      return "added";
        case GIT_DELTA_DELETED:    return "deleted";
        case GIT_DELTA_MODIFIED:   return "modified";
        case GIT_DELTA_RENAMED:    return "renamed";
        case GIT_DELTA_COPIED:     return "copied";
        case GIT_DELTA_TYPECHANGE: return "typechange";
        default:                   return "unknown";
    }
}

static const char *file_status_to_string(unsigned int flags, int *out_staged) {
    /* Check index (staged) flags first */
    if (flags & GIT_STATUS_INDEX_NEW) { *out_staged = 1; return "new"; }
    if (flags & GIT_STATUS_INDEX_MODIFIED) { *out_staged = 1; return "modified"; }
    if (flags & GIT_STATUS_INDEX_DELETED) { *out_staged = 1; return "deleted"; }
    if (flags & GIT_STATUS_INDEX_RENAMED) { *out_staged = 1; return "renamed"; }
    if (flags & GIT_STATUS_INDEX_TYPECHANGE) { *out_staged = 1; return "typechange"; }

    /* Check working tree (unstaged) flags */
    if (flags & GIT_STATUS_WT_NEW) { *out_staged = 0; return "new"; }
    if (flags & GIT_STATUS_WT_MODIFIED) { *out_staged = 0; return "modified"; }
    if (flags & GIT_STATUS_WT_DELETED) { *out_staged = 0; return "deleted"; }
    if (flags & GIT_STATUS_WT_RENAMED) { *out_staged = 0; return "renamed"; }
    if (flags & GIT_STATUS_WT_TYPECHANGE) { *out_staged = 0; return "typechange"; }

    *out_staged = 0;
    return "unknown";
}

static void check_git_error(int rc, const char *context) {
    if (rc < 0) {
        const git_error *err = git_error_last();
        fprintf(stderr, "%s: %s\n", context, err ? err->message : "unknown error");
        exit(1);
    }
}

/* ============================================================================
 * Element cleanup functions for inline struct arrays
 * ============================================================================ */

static void cleanup_git_commit_elem(void *p) {
    RtGitCommit *c = (RtGitCommit *)p;
    free(c->id_str);
    free(c->message_str);
    free(c->author_name);
    free(c->author_email_str);
}

static void cleanup_git_branch_elem(void *p) {
    RtGitBranch *b = (RtGitBranch *)p;
    free(b->name_str);
}

static void cleanup_git_remote_elem(void *p) {
    RtGitRemote *r = (RtGitRemote *)p;
    free(r->name_str);
    free(r->url_str);
}

static void cleanup_git_diff_elem(void *p) {
    RtGitDiff *d = (RtGitDiff *)p;
    free(d->path_str);
    free(d->status_str);
    free(d->old_path_str);
}

static void cleanup_git_status_elem(void *p) {
    RtGitStatus *s = (RtGitStatus *)p;
    free(s->path_str);
    free(s->status_str);
}

static void cleanup_git_tag_elem(void *p) {
    RtGitTag *t = (RtGitTag *)p;
    free(t->name_str);
    free(t->target_id_str);
    free(t->message_str);
}

/* ============================================================================
 * GitRepo Factory Functions
 * ============================================================================ */

__sn__GitRepo *sn_git_repo_open(char *path) {
        ensure_libgit2_initialized();

    git_repository *repo = NULL;
    int rc = git_repository_open(&repo, path);
    check_git_error(rc, "GitRepo.open");

    RtGitRepo *result = __sn__GitRepo__new();
    if (!result) {
        fprintf(stderr, "GitRepo.open: allocation failed\n");
        git_repository_free(repo);
        exit(1);
    }

    SET_REPO_PTR(result, repo);

    const char *workdir = git_repository_workdir(repo);
    const char *path_src = workdir ? workdir : path;
    result->path_str = arena_strdup_local(path_src);

    return result;
}

__sn__GitRepo *sn_git_repo_clone(char *url, char *path) {
        ensure_libgit2_initialized();

    git_repository *repo = NULL;
    git_clone_options opts = GIT_CLONE_OPTIONS_INIT;
    opts.fetch_opts.callbacks.credentials = git_credential_cb;
    cred_attempt_count = 0;

    int rc = git_clone(&repo, url, path, &opts);
    check_git_error(rc, "GitRepo.clone");

    RtGitRepo *result = __sn__GitRepo__new();
    if (!result) {
        fprintf(stderr, "GitRepo.clone: allocation failed\n");
        git_repository_free(repo);
        exit(1);
    }

    SET_REPO_PTR(result, repo);

    const char *workdir = git_repository_workdir(repo);
    const char *path_src = workdir ? workdir : path;
    result->path_str = arena_strdup_local(path_src);

    return result;
}

__sn__GitRepo *sn_git_repo_init(char *path) {
        ensure_libgit2_initialized();

    git_repository *repo = NULL;
    int rc = git_repository_init(&repo, path, 0);
    check_git_error(rc, "GitRepo.init");

    RtGitRepo *result = __sn__GitRepo__new();
    if (!result) {
        fprintf(stderr, "GitRepo.init: allocation failed\n");
        git_repository_free(repo);
        exit(1);
    }

    SET_REPO_PTR(result, repo);

    const char *workdir = git_repository_workdir(repo);
    const char *path_src = workdir ? workdir : path;
    result->path_str = arena_strdup_local(path_src);

    return result;
}

__sn__GitRepo *sn_git_repo_init_bare(char *path) {
        ensure_libgit2_initialized();

    git_repository *repo = NULL;
    int rc = git_repository_init(&repo, path, 1);
    check_git_error(rc, "GitRepo.initBare");

    RtGitRepo *result = __sn__GitRepo__new();
    if (!result) {
        fprintf(stderr, "GitRepo.initBare: allocation failed\n");
        git_repository_free(repo);
        exit(1);
    }

    SET_REPO_PTR(result, repo);
    result->path_str = arena_strdup_local(path);

    return result;
}

/* ============================================================================
 * GitRepo Status & Staging
 * ============================================================================ */

SnArray *sn_git_repo_status(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.status: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.status: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_status_list *status_list = NULL;
    git_status_options opts = GIT_STATUS_OPTIONS_INIT;
    opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED |
                 GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX |
                 GIT_STATUS_OPT_SORT_CASE_SENSITIVELY;

    int rc = git_status_list_new(&status_list, repo, &opts);
    check_git_error(rc, "GitRepo.status");

    size_t count = git_status_list_entrycount(status_list);

    /* Build array of inline RtGitStatus structs */
    SnArray *result_arr = sn_array_new(sizeof(RtGitStatus), 16);
    result_arr->elem_tag = SN_TAG_STRUCT;
    result_arr->elem_release = cleanup_git_status_elem;

    for (size_t i = 0; i < count; i++) {
        const git_status_entry *entry = git_status_byindex(status_list, i);
        if (!entry) continue;

        int is_staged = 0;
        const char *status_str = file_status_to_string(entry->status, &is_staged);

        const char *filepath = NULL;
        if (entry->head_to_index && entry->head_to_index->new_file.path) {
            filepath = entry->head_to_index->new_file.path;
        } else if (entry->index_to_workdir && entry->index_to_workdir->new_file.path) {
            filepath = entry->index_to_workdir->new_file.path;
        }
        if (!filepath) continue;

        RtGitStatus s = {0};
        s.path_str = arena_strdup_local(filepath);
        s.status_str = arena_strdup_local(status_str);
        s.is_staged = is_staged;

        sn_array_push(result_arr, &s);
    }

    git_status_list_free(status_list);
    return result_arr;
}

void sn_git_repo_add(__sn__GitRepo *self, char *path) {
    if (!self) {
        fprintf(stderr, "GitRepo.add: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.add: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_index *index = NULL;

    int rc = git_repository_index(&index, repo);
    check_git_error(rc, "GitRepo.add");

    rc = git_index_add_bypath(index, path);
    check_git_error(rc, "GitRepo.add");

    rc = git_index_write(index);
    check_git_error(rc, "GitRepo.add: write index");

    git_index_free(index);
}

void sn_git_repo_add_all(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.addAll: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.addAll: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_index *index = NULL;

    int rc = git_repository_index(&index, repo);
    check_git_error(rc, "GitRepo.addAll");

    git_strarray pathspec = { NULL, 0 };
    char *paths[] = { "." };
    pathspec.strings = paths;
    pathspec.count = 1;

    rc = git_index_add_all(index, &pathspec, 0, NULL, NULL);
    check_git_error(rc, "GitRepo.addAll");

    rc = git_index_write(index);
    check_git_error(rc, "GitRepo.addAll: write index");

    git_index_free(index);
}

void sn_git_repo_unstage(__sn__GitRepo *self, char *path) {
    if (!self) {
        fprintf(stderr, "GitRepo.unstage: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.unstage: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_reference *head_ref = NULL;
    git_object *head_commit = NULL;

    int rc = git_repository_head(&head_ref, repo);
    if (rc == 0) {
        rc = git_reference_peel(&head_commit, head_ref, GIT_OBJECT_COMMIT);
        check_git_error(rc, "GitRepo.unstage");
    }

    git_strarray pathspec = { NULL, 0 };
    char *paths[1];
    paths[0] = (char *)path;
    pathspec.strings = paths;
    pathspec.count = 1;

    rc = git_reset_default(repo, head_commit, &pathspec);
    check_git_error(rc, "GitRepo.unstage");

    if (head_commit) git_object_free(head_commit);
    if (head_ref) git_reference_free(head_ref);
}

/* ============================================================================
 * GitRepo Commits & Log
 * ============================================================================ */

static __sn__GitCommit create_commit_from_git(git_commit *commit) {
    RtGitCommit c = {0};

    /* Get commit ID as hex string */
    const git_oid *oid = git_commit_id(commit);
    char id_buf[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(id_buf, sizeof(id_buf), oid);
    c.id_str = arena_strdup_local(id_buf);

    /* Get message */
    const char *msg = git_commit_message(commit);
    c.message_str = arena_strdup_local(msg ? msg : "");

    /* Get author */
    const git_signature *author = git_commit_author(commit);
    if (author) {
        c.author_name = arena_strdup_local(author->name ? author->name : "");
        c.author_email_str = arena_strdup_local(author->email ? author->email : "");
        c.timestamp = (long long)author->when.time;
    } else {
        c.author_name = arena_strdup_local("");
        c.author_email_str = arena_strdup_local("");
        c.timestamp = 0;
    }

    return c;
}

__sn__GitCommit sn_git_repo_commit(__sn__GitRepo *self, char *message) {
    if (!self) {
        fprintf(stderr, "GitRepo.commit: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.commit: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_signature *sig = NULL;
    git_index *index = NULL;
    git_oid tree_oid, commit_oid;
    git_tree *tree = NULL;

    /* Create default signature */
    int rc = git_signature_default(&sig, repo);
    if (rc < 0) {
        /* Fallback: use generic signature */
        rc = git_signature_now(&sig, "Sindarin User", "user@sindarin.local");
        check_git_error(rc, "GitRepo.commit: create signature");
    }

    /* Get index and write tree */
    rc = git_repository_index(&index, repo);
    check_git_error(rc, "GitRepo.commit: get index");

    rc = git_index_write_tree(&tree_oid, index);
    check_git_error(rc, "GitRepo.commit: write tree");

    rc = git_tree_lookup(&tree, repo, &tree_oid);
    check_git_error(rc, "GitRepo.commit: lookup tree");

    /* Get parent commit (HEAD) if it exists */
    git_commit *parent = NULL;
    git_reference *head_ref = NULL;
    int parent_count = 0;
    const git_commit *parents[1] = { NULL };

    rc = git_repository_head(&head_ref, repo);
    if (rc == 0) {
        git_oid parent_oid;
        rc = git_reference_name_to_id(&parent_oid, repo, "HEAD");
        if (rc == 0) {
            rc = git_commit_lookup(&parent, repo, &parent_oid);
            if (rc == 0) {
                parents[0] = parent;
                parent_count = 1;
            }
        }
        git_reference_free(head_ref);
    }

    /* Create commit */
    rc = git_commit_create(&commit_oid, repo, "HEAD", sig, sig,
                           NULL, message, tree, parent_count, parents);
    check_git_error(rc, "GitRepo.commit");

    /* Get the created commit for returning */
    git_commit *new_commit = NULL;
    rc = git_commit_lookup(&new_commit, repo, &commit_oid);
    check_git_error(rc, "GitRepo.commit: lookup new commit");

    __sn__GitCommit result_commit = create_commit_from_git(new_commit);

    git_commit_free(new_commit);
    if (parent) git_commit_free(parent);
    git_tree_free(tree);
    git_index_free(index);
    git_signature_free(sig);

    return result_commit;
}

__sn__GitCommit sn_git_repo_commit_as(__sn__GitRepo *self, char *message,
                                     char *authorName, char *authorEmail) {
    if (!self) {
        fprintf(stderr, "GitRepo.commitAs: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.commitAs: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_signature *sig = NULL;
    git_index *index = NULL;
    git_oid tree_oid, commit_oid;
    git_tree *tree = NULL;

    /* Create signature from provided name/email */
    int rc = git_signature_now(&sig, authorName, authorEmail);
    check_git_error(rc, "GitRepo.commitAs: create signature");

    /* Get index and write tree */
    rc = git_repository_index(&index, repo);
    check_git_error(rc, "GitRepo.commitAs: get index");

    rc = git_index_write_tree(&tree_oid, index);
    check_git_error(rc, "GitRepo.commitAs: write tree");

    rc = git_tree_lookup(&tree, repo, &tree_oid);
    check_git_error(rc, "GitRepo.commitAs: lookup tree");

    /* Get parent commit (HEAD) if it exists */
    git_commit *parent = NULL;
    int parent_count = 0;
    const git_commit *parents[1] = { NULL };

    git_reference *head_ref = NULL;
    rc = git_repository_head(&head_ref, repo);
    if (rc == 0) {
        git_oid parent_oid;
        rc = git_reference_name_to_id(&parent_oid, repo, "HEAD");
        if (rc == 0) {
            rc = git_commit_lookup(&parent, repo, &parent_oid);
            if (rc == 0) {
                parents[0] = parent;
                parent_count = 1;
            }
        }
        git_reference_free(head_ref);
    }

    /* Create commit */
    rc = git_commit_create(&commit_oid, repo, "HEAD", sig, sig,
                           NULL, message, tree, parent_count, parents);
    check_git_error(rc, "GitRepo.commitAs");

    /* Get the created commit for returning */
    git_commit *new_commit = NULL;
    rc = git_commit_lookup(&new_commit, repo, &commit_oid);
    check_git_error(rc, "GitRepo.commitAs: lookup new commit");

    __sn__GitCommit result_commit = create_commit_from_git(new_commit);

    git_commit_free(new_commit);
    if (parent) git_commit_free(parent);
    git_tree_free(tree);
    git_index_free(index);
    git_signature_free(sig);

    return result_commit;
}

SnArray *sn_git_repo_log(__sn__GitRepo *self, long long maxCount) {
    if (!self) {
        fprintf(stderr, "GitRepo.log: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.log: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_revwalk *walker = NULL;

    int rc = git_revwalk_new(&walker, repo);
    check_git_error(rc, "GitRepo.log");

    rc = git_revwalk_push_head(walker);
    if (rc < 0) {
        /* Empty repository - no HEAD */
        git_revwalk_free(walker);
        return NULL;
    }

    git_revwalk_sorting(walker, GIT_SORT_TIME);

    /* Build array of inline RtGitCommit structs */
    SnArray *result_arr = sn_array_new(sizeof(RtGitCommit), 16);
    result_arr->elem_tag = SN_TAG_STRUCT;
    result_arr->elem_release = cleanup_git_commit_elem;
    size_t max = (size_t)(maxCount > 0 ? maxCount : 100);
    size_t count = 0;
    git_oid oid;

    while (count < max && git_revwalk_next(&oid, walker) == 0) {
        git_commit *commit = NULL;
        rc = git_commit_lookup(&commit, repo, &oid);
        if (rc < 0) continue;

        __sn__GitCommit result_commit = create_commit_from_git(commit);
        sn_array_push(result_arr, &result_commit);
        count++;

        git_commit_free(commit);
    }

    git_revwalk_free(walker);
    return result_arr;
}

__sn__GitCommit sn_git_repo_head_commit(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.head: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.head: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_oid head_oid;
    git_commit *commit = NULL;

    int rc = git_reference_name_to_id(&head_oid, repo, "HEAD");
    check_git_error(rc, "GitRepo.head: resolve HEAD");

    rc = git_commit_lookup(&commit, repo, &head_oid);
    check_git_error(rc, "GitRepo.head: lookup commit");

    __sn__GitCommit result_commit = create_commit_from_git(commit);
    git_commit_free(commit);

    return result_commit;
}

/* ============================================================================
 * GitRepo Branches
 * ============================================================================ */

SnArray *sn_git_repo_branches(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.branches: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.branches: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_branch_iterator *iter = NULL;

    int rc = git_branch_iterator_new(&iter, repo, GIT_BRANCH_ALL);
    check_git_error(rc, "GitRepo.branches");

    /* Build array of inline RtGitBranch structs */
    SnArray *result_arr = sn_array_new(sizeof(RtGitBranch), 16);
    result_arr->elem_tag = SN_TAG_STRUCT;
    result_arr->elem_release = cleanup_git_branch_elem;
    git_reference *ref = NULL;
    git_branch_t branch_type;

    while (git_branch_next(&ref, &branch_type, iter) == 0) {
        const char *branch_name = NULL;
        git_branch_name(&branch_name, ref);

        RtGitBranch b = {0};
        b.name_str = arena_strdup_local(branch_name ? branch_name : "");
        b.is_head = git_branch_is_head(ref) ? 1 : 0;
        b.is_remote = (branch_type == GIT_BRANCH_REMOTE) ? 1 : 0;

        sn_array_push(result_arr, &b);
        git_reference_free(ref);
    }

    git_branch_iterator_free(iter);
    return result_arr;
}

char *sn_git_repo_current_branch(__sn__GitRepo *self) {
    if (!self) {
        return strdup("");
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        return strdup("");
    }

    git_repository *repo = REPO_PTR(self);
    git_reference *head_ref = NULL;

    int rc = git_repository_head(&head_ref, repo);
    if (rc < 0) {
        return strdup("");
    }

    const char *branch_name = NULL;
    rc = git_branch_name(&branch_name, head_ref);
    char *result = strdup((rc == 0 && branch_name) ? branch_name : "");

    git_reference_free(head_ref);
    return result;
}

__sn__GitBranch sn_git_repo_create_branch(__sn__GitRepo *self, char *name) {
    if (!self) {
        fprintf(stderr, "GitRepo.createBranch: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.createBranch: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_reference *new_ref = NULL;
    git_commit *head_commit = NULL;
    git_oid head_oid;

    int rc = git_reference_name_to_id(&head_oid, repo, "HEAD");
    check_git_error(rc, "GitRepo.createBranch: resolve HEAD");

    rc = git_commit_lookup(&head_commit, repo, &head_oid);
    check_git_error(rc, "GitRepo.createBranch: lookup HEAD");

    rc = git_branch_create(&new_ref, repo, name, head_commit, 0);
    check_git_error(rc, "GitRepo.createBranch");

    RtGitBranch b = {0};
    b.name_str = arena_strdup_local(name);
    b.is_head = 0;
    b.is_remote = 0;

    git_reference_free(new_ref);
    git_commit_free(head_commit);

    return b;
}

void sn_git_repo_delete_branch(__sn__GitRepo *self, char *name) {
    if (!self) {
        fprintf(stderr, "GitRepo.deleteBranch: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.deleteBranch: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_reference *ref = NULL;

    int rc = git_branch_lookup(&ref, repo, name, GIT_BRANCH_LOCAL);
    check_git_error(rc, "GitRepo.deleteBranch: lookup");

    rc = git_branch_delete(ref);
    check_git_error(rc, "GitRepo.deleteBranch");

    git_reference_free(ref);
}

void sn_git_repo_checkout(__sn__GitRepo *self, char *refName) {
    if (!self) {
        fprintf(stderr, "GitRepo.checkout: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.checkout: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_object *target = NULL;
    git_reference *branch_ref = NULL;

    /* Try to look up as a branch first */
    int rc = git_branch_lookup(&branch_ref, repo, refName, GIT_BRANCH_LOCAL);
    if (rc == 0) {
        /* It's a local branch - checkout its tree */
        rc = git_reference_peel(&target, branch_ref, GIT_OBJECT_COMMIT);
        check_git_error(rc, "GitRepo.checkout: peel branch");
    } else {
        /* Try as a generic revision */
        rc = git_revparse_single(&target, repo, refName);
        check_git_error(rc, "GitRepo.checkout: resolve ref");
    }

    /* Checkout the tree */
    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

    rc = git_checkout_tree(repo, target, &checkout_opts);
    check_git_error(rc, "GitRepo.checkout: checkout tree");

    /* Update HEAD */
    if (branch_ref) {
        rc = git_repository_set_head(repo, git_reference_name(branch_ref));
        check_git_error(rc, "GitRepo.checkout: set HEAD");
        git_reference_free(branch_ref);
    } else {
        /* Detached HEAD */
        const git_oid *oid = git_object_id(target);
        rc = git_repository_set_head_detached(repo, oid);
        check_git_error(rc, "GitRepo.checkout: detach HEAD");
    }

    git_object_free(target);
}

/* ============================================================================
 * GitRepo Remotes
 * ============================================================================ */

SnArray *sn_git_repo_remotes(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.remotes: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.remotes: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_strarray remote_names = { NULL, 0 };

    int rc = git_remote_list(&remote_names, repo);
    check_git_error(rc, "GitRepo.remotes");

    /* Build array of inline RtGitRemote structs */
    SnArray *result_arr = sn_array_new(sizeof(RtGitRemote), 16);
    result_arr->elem_tag = SN_TAG_STRUCT;
    result_arr->elem_release = cleanup_git_remote_elem;

    for (size_t i = 0; i < remote_names.count; i++) {
        git_remote *remote = NULL;
        rc = git_remote_lookup(&remote, repo, remote_names.strings[i]);
        if (rc < 0) continue;

        RtGitRemote r = {0};
        r.name_str = arena_strdup_local(git_remote_name(remote));
        r.url_str = arena_strdup_local(git_remote_url(remote));

        sn_array_push(result_arr, &r);
        git_remote_free(remote);
    }

    git_strarray_dispose(&remote_names);
    return result_arr;
}

__sn__GitRemote sn_git_repo_add_remote(__sn__GitRepo *self,
                                      char *name, char *url) {
    if (!self) {
        fprintf(stderr, "GitRepo.addRemote: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.addRemote: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_remote *remote = NULL;

    int rc = git_remote_create(&remote, repo, name, url);
    check_git_error(rc, "GitRepo.addRemote");

    RtGitRemote r = {0};
    r.name_str = arena_strdup_local(name);
    r.url_str = arena_strdup_local(url);

    git_remote_free(remote);
    return r;
}

void sn_git_repo_remove_remote(__sn__GitRepo *self, char *name) {
    if (!self) {
        fprintf(stderr, "GitRepo.removeRemote: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.removeRemote: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    int rc = git_remote_delete(repo, name);
    check_git_error(rc, "GitRepo.removeRemote");
}

/* ============================================================================
 * GitRepo Network Operations
 * ============================================================================ */

void sn_git_repo_fetch(__sn__GitRepo *self, char *remoteName) {
    if (!self) {
        fprintf(stderr, "GitRepo.fetch: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.fetch: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_remote *remote = NULL;

    int rc = git_remote_lookup(&remote, repo, remoteName);
    check_git_error(rc, "GitRepo.fetch: lookup remote");

    git_fetch_options opts = GIT_FETCH_OPTIONS_INIT;
    opts.callbacks.credentials = git_credential_cb;
    cred_attempt_count = 0;

    rc = git_remote_fetch(remote, NULL, &opts, NULL);
    check_git_error(rc, "GitRepo.fetch");

    git_remote_free(remote);
}

void sn_git_repo_push(__sn__GitRepo *self, char *remoteName) {
    if (!self) {
        fprintf(stderr, "GitRepo.push: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.push: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_remote *remote = NULL;

    int rc = git_remote_lookup(&remote, repo, remoteName);
    check_git_error(rc, "GitRepo.push: lookup remote");

    /* Get current branch refspec */
    git_reference *head_ref = NULL;
    rc = git_repository_head(&head_ref, repo);
    check_git_error(rc, "GitRepo.push: get HEAD");

    const char *ref_name = git_reference_name(head_ref);
    git_strarray refspecs = { NULL, 0 };
    char *refspec_str = (char *)malloc(strlen(ref_name) + 1);
    if (!refspec_str) {
        fprintf(stderr, "GitRepo.push: allocation failed\n");
        git_reference_free(head_ref);
        git_remote_free(remote);
        exit(1);
    }
    strcpy(refspec_str, ref_name);
    refspecs.strings = &refspec_str;
    refspecs.count = 1;

    git_push_options opts = GIT_PUSH_OPTIONS_INIT;
    opts.callbacks.credentials = git_credential_cb;
    cred_attempt_count = 0;

    rc = git_remote_push(remote, &refspecs, &opts);
    check_git_error(rc, "GitRepo.push");

    free(refspec_str);
    git_reference_free(head_ref);
    git_remote_free(remote);
}

void sn_git_repo_pull(__sn__GitRepo *self, char *remoteName) {
    
    if (!self) {
        fprintf(stderr, "GitRepo.pull: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.pull: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_remote *remote = NULL;

    /* Fetch first */
    int rc = git_remote_lookup(&remote, repo, remoteName);
    check_git_error(rc, "GitRepo.pull: lookup remote");

    git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
    fetch_opts.callbacks.credentials = git_credential_cb;
    cred_attempt_count = 0;

    rc = git_remote_fetch(remote, NULL, &fetch_opts, NULL);
    check_git_error(rc, "GitRepo.pull: fetch");

    git_remote_free(remote);

    /* Get the current branch's upstream */
    git_reference *head_ref = NULL;
    rc = git_repository_head(&head_ref, repo);
    check_git_error(rc, "GitRepo.pull: get HEAD");

    /* Get the FETCH_HEAD */
    git_oid fetch_head_oid;
    rc = git_reference_name_to_id(&fetch_head_oid, repo, "FETCH_HEAD");
    if (rc < 0) {
        /* No FETCH_HEAD means nothing to merge */
        git_reference_free(head_ref);
        return;
    }

    /* Perform merge analysis */
    git_annotated_commit *fetch_head_commit = NULL;
    rc = git_annotated_commit_lookup(&fetch_head_commit, repo, &fetch_head_oid);
    check_git_error(rc, "GitRepo.pull: lookup fetch head");

    git_merge_analysis_t analysis;
    git_merge_preference_t preference;
    const git_annotated_commit *their_heads[1] = { fetch_head_commit };

    rc = git_merge_analysis(&analysis, &preference, repo, their_heads, 1);
    check_git_error(rc, "GitRepo.pull: merge analysis");

    if (analysis & GIT_MERGE_ANALYSIS_UP_TO_DATE) {
        /* Already up to date */
    } else if (analysis & GIT_MERGE_ANALYSIS_FASTFORWARD) {
        /* Fast-forward */
        git_reference *new_ref = NULL;
        const char *ref_name = git_reference_name(head_ref);

        rc = git_reference_set_target(&new_ref, head_ref, &fetch_head_oid, "pull: fast-forward");
        check_git_error(rc, "GitRepo.pull: fast-forward");

        /* Checkout the new tree */
        git_object *target = NULL;
        rc = git_object_lookup(&target, repo, &fetch_head_oid, GIT_OBJECT_COMMIT);
        if (rc == 0) {
            git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
            checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
            git_checkout_tree(repo, target, &checkout_opts);
            git_object_free(target);
        }

        if (new_ref) git_reference_free(new_ref);
        (void)ref_name;
    } else if (analysis & GIT_MERGE_ANALYSIS_NORMAL) {
        /* Normal merge */
        git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

        rc = git_merge(repo, their_heads, 1, &merge_opts, &checkout_opts);
        check_git_error(rc, "GitRepo.pull: merge");

        /* Auto-commit the merge if there are no conflicts */
        git_index *index = NULL;
        rc = git_repository_index(&index, repo);
        if (rc == 0 && !git_index_has_conflicts(index)) {
            git_oid tree_oid, commit_oid;
            git_tree *tree = NULL;
            git_signature *sig = NULL;
            git_commit *head_c = NULL;
            git_commit *fetch_c = NULL;

            git_signature_default(&sig, repo);
            if (!sig) git_signature_now(&sig, "Sindarin User", "user@sindarin.local");

            git_index_write_tree(&tree_oid, index);
            git_tree_lookup(&tree, repo, &tree_oid);

            git_oid head_oid;
            git_reference_name_to_id(&head_oid, repo, "HEAD");
            git_commit_lookup(&head_c, repo, &head_oid);
            git_commit_lookup(&fetch_c, repo, &fetch_head_oid);

            const git_commit *parents[2] = { head_c, fetch_c };
            git_commit_create(&commit_oid, repo, "HEAD", sig, sig,
                              NULL, "Merge remote changes", tree, 2, parents);

            if (sig) git_signature_free(sig);
            if (tree) git_tree_free(tree);
            if (head_c) git_commit_free(head_c);
            if (fetch_c) git_commit_free(fetch_c);

            git_repository_state_cleanup(repo);
        }
        if (index) git_index_free(index);
    }

    git_annotated_commit_free(fetch_head_commit);
    git_reference_free(head_ref);
}

/* ============================================================================
 * GitRepo Diff
 * ============================================================================ */

static SnArray *build_diff_array_h(git_diff *diff) {
    size_t num_deltas = git_diff_num_deltas(diff);

    /* Build array of inline RtGitDiff structs */
    SnArray *result_arr = sn_array_new(sizeof(RtGitDiff), 16);
    result_arr->elem_tag = SN_TAG_STRUCT;
    result_arr->elem_release = cleanup_git_diff_elem;

    for (size_t i = 0; i < num_deltas; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (!delta) continue;

        RtGitDiff d = {0};
        d.path_str = arena_strdup_local(delta->new_file.path ? delta->new_file.path : "");
        d.status_str = arena_strdup_local(diff_status_to_string(delta->status));
        d.old_path_str = arena_strdup_local(delta->old_file.path ? delta->old_file.path : "");

        sn_array_push(result_arr, &d);
    }

    return result_arr;
}

SnArray *sn_git_repo_diff(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.diff: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.diff: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_diff *diff = NULL;

    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    int rc = git_diff_index_to_workdir(&diff, repo, NULL, &opts);
    check_git_error(rc, "GitRepo.diff");

    SnArray *result = build_diff_array_h(diff);
    git_diff_free(diff);
    return result;
}

SnArray *sn_git_repo_diff_staged(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.diffStaged: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.diffStaged: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_diff *diff = NULL;
    git_object *head_obj = NULL;
    git_tree *head_tree = NULL;

    /* Get HEAD tree for comparison */
    int rc = git_revparse_single(&head_obj, repo, "HEAD^{tree}");
    if (rc == 0) {
        head_tree = (git_tree *)head_obj;
    }

    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    rc = git_diff_tree_to_index(&diff, repo, head_tree, NULL, &opts);
    check_git_error(rc, "GitRepo.diffStaged");

    SnArray *result = build_diff_array_h(diff);

    git_diff_free(diff);
    if (head_obj) git_object_free(head_obj);
    return result;
}

/* ============================================================================
 * GitRepo Tags
 * ============================================================================ */

SnArray *sn_git_repo_tags(__sn__GitRepo *self) {
    if (!self) {
        fprintf(stderr, "GitRepo.tags: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.tags: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_strarray tag_names = { NULL, 0 };

    int rc = git_tag_list(&tag_names, repo);
    check_git_error(rc, "GitRepo.tags");

    /* Build array of inline RtGitTag structs */
    SnArray *result_arr = sn_array_new(sizeof(RtGitTag), 16);
    result_arr->elem_tag = SN_TAG_STRUCT;
    result_arr->elem_release = cleanup_git_tag_elem;

    for (size_t i = 0; i < tag_names.count; i++) {
        const char *tag_name = tag_names.strings[i];

        RtGitTag t = {0};
        t.name_str = arena_strdup_local(tag_name);

        /* Try to look up as annotated tag */
        char refname[256];
        snprintf(refname, sizeof(refname), "refs/tags/%s", tag_name);

        git_oid tag_oid;
        rc = git_reference_name_to_id(&tag_oid, repo, refname);
        if (rc == 0) {
            char oid_buf[GIT_OID_SHA1_HEXSIZE + 1];
            git_oid_tostr(oid_buf, sizeof(oid_buf), &tag_oid);

            git_tag *tag_obj = NULL;
            rc = git_tag_lookup(&tag_obj, repo, &tag_oid);
            if (rc == 0) {
                /* Annotated tag */
                t.is_lightweight = 0;
                const git_oid *target_oid = git_tag_target_id(tag_obj);
                char target_buf[GIT_OID_SHA1_HEXSIZE + 1];
                git_oid_tostr(target_buf, sizeof(target_buf), target_oid);
                t.target_id_str = arena_strdup_local(target_buf);

                const char *msg = git_tag_message(tag_obj);
                t.message_str = arena_strdup_local(msg ? msg : "");

                git_tag_free(tag_obj);
            } else {
                /* Lightweight tag - the OID points directly to a commit */
                t.is_lightweight = 1;
                t.target_id_str = arena_strdup_local(oid_buf);
                t.message_str = arena_strdup_local("");
            }
        } else {
            t.target_id_str = arena_strdup_local("");
            t.message_str = arena_strdup_local("");
            t.is_lightweight = 1;
        }

        sn_array_push(result_arr, &t);
    }

    git_strarray_dispose(&tag_names);
    return result_arr;
}

__sn__GitTag sn_git_repo_create_tag(__sn__GitRepo *self, char *name) {
    if (!self) {
        fprintf(stderr, "GitRepo.createTag: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.createTag: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_oid head_oid;
    git_object *target = NULL;

    int rc = git_reference_name_to_id(&head_oid, repo, "HEAD");
    check_git_error(rc, "GitRepo.createTag: resolve HEAD");

    rc = git_object_lookup(&target, repo, &head_oid, GIT_OBJECT_COMMIT);
    check_git_error(rc, "GitRepo.createTag: lookup HEAD");

    git_oid tag_oid;
    rc = git_tag_create_lightweight(&tag_oid, repo, name, target, 0);
    check_git_error(rc, "GitRepo.createTag");

    char oid_buf[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_buf, sizeof(oid_buf), &head_oid);

    RtGitTag t = {0};
    t.name_str = arena_strdup_local(name);
    t.target_id_str = arena_strdup_local(oid_buf);
    t.message_str = arena_strdup_local("");
    t.is_lightweight = 1;

    git_object_free(target);
    return t;
}

__sn__GitTag sn_git_repo_create_annotated_tag(__sn__GitRepo *self,
                                             char *name, char *message) {
    if (!self) {
        fprintf(stderr, "GitRepo.createAnnotatedTag: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.createAnnotatedTag: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    git_oid head_oid, tag_oid;
    git_object *target = NULL;
    git_signature *sig = NULL;

    int rc = git_reference_name_to_id(&head_oid, repo, "HEAD");
    check_git_error(rc, "GitRepo.createAnnotatedTag: resolve HEAD");

    rc = git_object_lookup(&target, repo, &head_oid, GIT_OBJECT_COMMIT);
    check_git_error(rc, "GitRepo.createAnnotatedTag: lookup HEAD");

    rc = git_signature_default(&sig, repo);
    if (rc < 0) {
        rc = git_signature_now(&sig, "Sindarin User", "user@sindarin.local");
        check_git_error(rc, "GitRepo.createAnnotatedTag: create signature");
    }

    rc = git_tag_create(&tag_oid, repo, name, target, sig, message, 0);
    check_git_error(rc, "GitRepo.createAnnotatedTag");

    char oid_buf[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_buf, sizeof(oid_buf), &head_oid);

    RtGitTag t = {0};
    t.name_str = arena_strdup_local(name);
    t.target_id_str = arena_strdup_local(oid_buf);
    t.message_str = arena_strdup_local(message ? message : "");
    t.is_lightweight = 0;

    git_signature_free(sig);
    git_object_free(target);
    return t;
}

void sn_git_repo_delete_tag(__sn__GitRepo *self, char *name) {
    if (!self) {
        fprintf(stderr, "GitRepo.deleteTag: repository is closed\n");
        exit(1);
    }
    /* self is already the right type */
    if (!REPO_PTR(self)) {
        fprintf(stderr, "GitRepo.deleteTag: repository is closed\n");
        exit(1);
    }

    git_repository *repo = REPO_PTR(self);
    int rc = git_tag_delete(repo, name);
    check_git_error(rc, "GitRepo.deleteTag");
}

/* ============================================================================
 * GitRepo Getters
 * ============================================================================ */

char *sn_git_repo_get_path(__sn__GitRepo *self) {
    if (!self) {
        return strdup("");
    }
    /* self is already the right type */
    if (!self->path_str) {
        return strdup("");
    }
    return strdup(self->path_str);
}

bool sn_git_repo_is_bare(__sn__GitRepo *self) {
    if (!self) return 0;
    /* self is already the right type */
    if (!REPO_PTR(self)) return 0;
    return git_repository_is_bare(REPO_PTR(self)) ? 1 : 0;
}

/* ============================================================================
 * GitRepo Lifecycle
 * ============================================================================ */

void sn_git_repo_close(__sn__GitRepo *self) {
    if (!self) return;

    git_repository *repo = REPO_PTR(self);

    if (repo) {
        git_repository_free(repo);
    }
    SET_REPO_PTR(self, NULL);
}

/* ============================================================================
 * GitCommit Getters
 * ============================================================================ */

char *sn_git_commit_get_id(__sn__GitCommit *commit) {
    if (!commit || !commit->id_str) return strdup("");
    return strdup(commit->id_str);
}

char *sn_git_commit_get_message(__sn__GitCommit *commit) {
    if (!commit || !commit->message_str) return strdup("");
    return strdup(commit->message_str);
}

char *sn_git_commit_get_author(__sn__GitCommit *commit) {
    if (!commit || !commit->author_name) return strdup("");
    return strdup(commit->author_name);
}

char *sn_git_commit_get_email(__sn__GitCommit *commit) {
    if (!commit || !commit->author_email_str) return strdup("");
    return strdup(commit->author_email_str);
}

long long sn_git_commit_get_timestamp(__sn__GitCommit *commit) {
    if (!commit) return 0;
    return commit->timestamp;
}

/* ============================================================================
 * GitBranch Getters
 * ============================================================================ */

char *sn_git_branch_get_name(__sn__GitBranch *branch) {
    if (!branch || !branch->name_str) return strdup("");
    return strdup(branch->name_str);
}

bool sn_git_branch_is_head(__sn__GitBranch *branch) {
    if (!branch) return 0;
    return branch->is_head;
}

bool sn_git_branch_is_remote(__sn__GitBranch *branch) {
    if (!branch) return 0;
    return branch->is_remote;
}

/* ============================================================================
 * GitRemote Getters
 * ============================================================================ */

char *sn_git_remote_get_name(__sn__GitRemote *remote) {
    if (!remote || !remote->name_str) return strdup("");
    return strdup(remote->name_str);
}

char *sn_git_remote_get_url(__sn__GitRemote *remote) {
    if (!remote || !remote->url_str) return strdup("");
    return strdup(remote->url_str);
}

/* ============================================================================
 * GitDiff Getters
 * ============================================================================ */

char *sn_git_diff_get_path(__sn__GitDiff *diff) {
    if (!diff || !diff->path_str) return strdup("");
    return strdup(diff->path_str);
}

char *sn_git_diff_get_status(__sn__GitDiff *diff) {
    if (!diff || !diff->status_str) return strdup("");
    return strdup(diff->status_str);
}

char *sn_git_diff_get_old_path(__sn__GitDiff *diff) {
    if (!diff || !diff->old_path_str) return strdup("");
    return strdup(diff->old_path_str);
}

/* ============================================================================
 * GitStatus Getters
 * ============================================================================ */

char *sn_git_status_get_path(__sn__GitStatus *status) {
    if (!status || !status->path_str) return strdup("");
    return strdup(status->path_str);
}

char *sn_git_status_get_status(__sn__GitStatus *status) {
    if (!status || !status->status_str) return strdup("");
    return strdup(status->status_str);
}

bool sn_git_status_is_staged(__sn__GitStatus *status) {
    if (!status) return 0;
    return status->is_staged;
}

/* ============================================================================
 * GitTag Getters
 * ============================================================================ */

char *sn_git_tag_get_name(__sn__GitTag *tag) {
    if (!tag || !tag->name_str) return strdup("");
    return strdup(tag->name_str);
}

char *sn_git_tag_get_target_id(__sn__GitTag *tag) {
    if (!tag || !tag->target_id_str) return strdup("");
    return strdup(tag->target_id_str);
}

char *sn_git_tag_get_message(__sn__GitTag *tag) {
    if (!tag || !tag->message_str) return strdup("");
    return strdup(tag->message_str);
}

bool sn_git_tag_is_lightweight(__sn__GitTag *tag) {
    if (!tag) return 1;
    return tag->is_lightweight;
}
