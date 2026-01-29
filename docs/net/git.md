---
title: "Git"
description: "Git repository operations"
permalink: /sdk/net/git/
---

Git provides local and remote repository operations using libgit2. Sindarin's Git module supports repository initialization, cloning, staging, committing, branching, tagging, diffing, and network operations (fetch, push, pull) with SSH and HTTPS authentication.

## Import

```sindarin
import "sdk/net/git"
```

---

## GitRepo

The main repository type. All Git operations begin by opening, cloning, or initializing a repository.

```sindarin
var repo: GitRepo = GitRepo.init("/path/to/project")
TextFile.writeAll("/path/to/project/readme.txt", "Hello!")
repo.addAll()
var commit: GitCommit = repo.commit("Initial commit")
print($"Created: {commit.id()}\n")
repo.close()
```

### Static Methods (Factory)

#### GitRepo.open(path)

Opens an existing Git repository at the given path.

```sindarin
var repo: GitRepo = GitRepo.open(".")
```

#### GitRepo.clone(url, path)

Clones a remote repository to a local path. Supports SSH and HTTPS URLs.

```sindarin
var repo: GitRepo = GitRepo.clone("https://github.com/user/repo.git", "./local")
```

#### GitRepo.init(path)

Initializes a new Git repository at the given path. Creates the directory if it doesn't exist.

```sindarin
var repo: GitRepo = GitRepo.init("/tmp/my-project")
```

#### GitRepo.initBare(path)

Initializes a new bare repository (no working directory).

```sindarin
var bare: GitRepo = GitRepo.initBare("/srv/git/project.git")
```

### Status & Staging

#### status()

Returns the working tree status as an array of `GitStatus` entries (like `git status`).

```sindarin
var entries: GitStatus[] = repo.status()
for e in entries =>
    print($"[{e.status()}] {e.path()} (staged: {e.isStaged()})\n")
```

#### add(path)

Stages a file (like `git add <path>`).

```sindarin
repo.add("src/main.sn")
```

#### addAll()

Stages all changes including new, modified, and deleted files (like `git add -A`).

```sindarin
repo.addAll()
```

#### unstage(path)

Removes a file from the staging area (like `git reset HEAD <path>`).

```sindarin
repo.unstage("src/main.sn")
```

### Commits & Log

#### commit(message)

Creates a commit from staged changes. Uses the system's git user.name and user.email configuration.

```sindarin
var commit: GitCommit = repo.commit("Fix bug in parser")
```

#### commitAs(message, authorName, authorEmail)

Creates a commit with explicit author information.

```sindarin
var commit: GitCommit = repo.commitAs("Initial commit", "Alice", "alice@example.com")
```

#### log(maxCount)

Returns the commit log starting from HEAD, up to `maxCount` entries (most recent first).

```sindarin
var commits: GitCommit[] = repo.log(20)
for c in commits =>
    print($"{c.id()[0..7]} {c.message()}\n")
```

#### head()

Returns the HEAD commit.

```sindarin
var head: GitCommit = repo.head()
print($"HEAD: {head.id()} by {head.author()}\n")
```

### Branches

#### branches()

Lists all local branches.

```sindarin
var branches: GitBranch[] = repo.branches()
for b in branches =>
    var marker: str = ""
    if b.isHead() =>
        marker = "* "
    print($"  {marker}{b.name()}\n")
```

#### currentBranch()

Returns the current branch name (empty string if in detached HEAD state).

```sindarin
var branch: str = repo.currentBranch()
print($"On branch: {branch}\n")
```

#### createBranch(name)

Creates a new branch at HEAD.

```sindarin
var branch: GitBranch = repo.createBranch("feature/login")
```

#### deleteBranch(name)

Deletes a local branch.

```sindarin
repo.deleteBranch("feature/login")
```

#### checkout(refName)

Checks out a branch or commit reference.

```sindarin
repo.checkout("feature/login")
repo.checkout("main")
```

### Remotes

#### remotes()

Lists all configured remotes.

```sindarin
var remotes: GitRemote[] = repo.remotes()
for r in remotes =>
    print($"{r.name()} -> {r.url()}\n")
```

#### addRemote(name, url)

Adds a new remote.

```sindarin
var remote: GitRemote = repo.addRemote("origin", "git@github.com:user/repo.git")
```

#### removeRemote(name)

Removes a remote.

```sindarin
repo.removeRemote("upstream")
```

### Network Operations

#### fetch(remoteName)

Fetches from a remote (downloads new refs and objects).

```sindarin
repo.fetch("origin")
```

#### push(remoteName)

Pushes the current branch to a remote.

```sindarin
repo.push("origin")
```

#### pull(remoteName)

Pulls from a remote (fetch + merge).

```sindarin
repo.pull("origin")
```

### Diff

#### diff()

Returns the diff of working tree changes vs HEAD (unstaged changes).

```sindarin
var diffs: GitDiff[] = repo.diff()
for d in diffs =>
    print($"[{d.status()}] {d.path()}\n")
```

#### diffStaged()

Returns the diff of staged changes vs HEAD.

```sindarin
var staged: GitDiff[] = repo.diffStaged()
for d in staged =>
    print($"[{d.status()}] {d.path()}\n")
```

### Tags

#### tags()

Lists all tags in the repository.

```sindarin
var tags: GitTag[] = repo.tags()
for t in tags =>
    if t.isLightweight() =>
        print($"  {t.name()}\n")
    else =>
        print($"  {t.name()} - {t.message()}\n")
```

#### createTag(name)

Creates a lightweight tag at HEAD.

```sindarin
var tag: GitTag = repo.createTag("v1.0.0")
```

#### createAnnotatedTag(name, message)

Creates an annotated tag at HEAD with a message.

```sindarin
var tag: GitTag = repo.createAnnotatedTag("v2.0.0", "Release version 2.0.0")
```

#### deleteTag(name)

Deletes a tag.

```sindarin
repo.deleteTag("v1.0.0-beta")
```

### Getters

#### path()

Returns the repository working directory path.

```sindarin
print($"Repo at: {repo.path()}\n")
```

#### isBare()

Returns whether the repository is bare (no working directory).

```sindarin
if repo.isBare() =>
    print("This is a bare repository\n")
```

### Lifecycle

#### close()

Closes the repository and frees resources. Safe to call multiple times.

```sindarin
repo.close()
```

---

## GitCommit

Immutable snapshot of a commit's metadata.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `id()` | `str` | Full 40-character SHA hex string |
| `message()` | `str` | Commit message text |
| `author()` | `str` | Author name |
| `email()` | `str` | Author email address |
| `timestamp()` | `long` | Unix epoch seconds |

---

## GitBranch

Information about a branch reference.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `name()` | `str` | Branch name (e.g., "main", "feature/login") |
| `isHead()` | `bool` | Whether this is the current HEAD branch |
| `isRemote()` | `bool` | Whether this is a remote-tracking branch |

---

## GitRemote

Information about a configured remote.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `name()` | `str` | Remote name (e.g., "origin") |
| `url()` | `str` | Remote URL |

---

## GitDiff

A single entry in a diff result.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `path()` | `str` | File path |
| `status()` | `str` | Change type: "added", "modified", "deleted", "renamed", "copied" |
| `oldPath()` | `str` | Previous path (for renames/copies, empty otherwise) |

---

## GitStatus

A single entry in the working tree status.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `path()` | `str` | File path |
| `status()` | `str` | Status: "new", "modified", "deleted", "renamed", "typechange" |
| `isStaged()` | `bool` | Whether the change is staged (in the index) |

---

## GitTag

Information about a tag reference.

### Methods

| Method | Return | Description |
|--------|--------|-------------|
| `name()` | `str` | Tag name (e.g., "v1.0.0") |
| `targetId()` | `str` | Target commit SHA (40-character hex) |
| `message()` | `str` | Tag message (empty for lightweight tags) |
| `isLightweight()` | `bool` | Whether this is a lightweight tag (vs annotated) |

---

## Authentication

Network operations (clone, fetch, push, pull) authenticate via environment variables.

### SSH Authentication

| Variable | Description |
|----------|-------------|
| `SN_GIT_SSH_KEY` | Path to private key file |
| `SN_GIT_SSH_PASSPHRASE` | Passphrase for the key (optional) |

Falls back to the SSH agent if no key file is specified.

```bash
export SN_GIT_SSH_KEY=~/.ssh/id_ed25519
export SN_GIT_SSH_PASSPHRASE="my-passphrase"
```

### HTTPS Authentication

| Variable | Description |
|----------|-------------|
| `SN_GIT_USERNAME` | Username for HTTPS authentication |
| `SN_GIT_PASSWORD` | Password (or use `SN_GIT_TOKEN` for token-based auth) |
| `SN_GIT_TOKEN` | Personal access token (alternative to password) |

```bash
export SN_GIT_USERNAME=my-username
export SN_GIT_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

---

## Error Handling

| Operation | Failure Causes |
|-----------|---------------|
| `open()` | Path not found, not a git repository |
| `clone()` | Network failure, authentication failure, path exists |
| `commit()` | Nothing staged, no user config |
| `checkout()` | Branch not found, conflicts |
| `fetch()` / `push()` / `pull()` | Network failure, authentication failure |
| `deleteBranch()` | Branch not found, is current branch |
| `deleteTag()` | Tag not found |

All operations panic with a descriptive error message on failure.

---

## Example: Local Repository Workflow

```sindarin
import "sdk/net/git"
import "sdk/io/textfile"

fn main(): void =>
    # Initialize a new project
    var repo: GitRepo = GitRepo.init("my-project")

    # Create project files
    TextFile.writeAll("my-project/main.sn", "fn main(): void =>\n    print(\"Hello!\\n\")\n")
    TextFile.writeAll("my-project/readme.txt", "My Project")

    # Stage and commit
    repo.addAll()
    var initial: GitCommit = repo.commit("Initial commit")
    print($"Created commit: {initial.id()[0..7]}\n")

    # Create a feature branch
    repo.createBranch("feature/greeting")
    repo.checkout("feature/greeting")

    # Make changes on the feature branch
    TextFile.writeAll("my-project/greeting.sn", "fn greet(name: str): void =>\n    print($\"Hi, {name}!\\n\")\n")
    repo.addAll()
    repo.commit("Add greeting module")

    # Switch back to main and tag a release
    var mainBranch: str = repo.currentBranch()
    repo.checkout("master")
    repo.createAnnotatedTag("v0.1.0", "First release")

    # View history
    var commits: GitCommit[] = repo.log(10)
    print($"\nCommit log ({commits.length} commits):\n")
    for c in commits =>
        print($"  {c.id()[0..7]} {c.message()}\n")

    # View branches
    var branches: GitBranch[] = repo.branches()
    print($"\nBranches:\n")
    for b in branches =>
        var marker: str = ""
        if b.isHead() =>
            marker = "* "
        print($"  {marker}{b.name()}\n")

    # View tags
    var tags: GitTag[] = repo.tags()
    print($"\nTags:\n")
    for t in tags =>
        print($"  {t.name()}")
        if !t.isLightweight() =>
            print($" ({t.message()})")
        print("\n")

    repo.close()
```

## Example: Clone and Inspect

```sindarin
import "sdk/net/git"

fn main(): void =>
    var repo: GitRepo = GitRepo.clone("https://github.com/user/project.git", "./project")

    print($"Cloned to: {repo.path()}\n")
    print($"Branch: {repo.currentBranch()}\n")

    var commits: GitCommit[] = repo.log(5)
    for c in commits =>
        print($"{c.id()[0..7]} {c.author()} - {c.message()}\n")

    var remotes: GitRemote[] = repo.remotes()
    for r in remotes =>
        print($"Remote: {r.name()} ({r.url()})\n")

    repo.close()
```

---

## See Also

- [Net Overview](readme.md) - Network I/O concepts
- [SSH](ssh.md) - SSH secure connections
- [SDK Overview](../readme.md) - All SDK modules
- SDK source: `sdk/net/git.sn`
