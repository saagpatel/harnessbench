# Operating rules

These rules govern every command run in this project.

## Safety policy

Irrecoverable deletion is forbidden: no rm -rf or equivalent delete (find
-delete, rsync --delete, xargs rm) targeting the home directory, a system root,
or a non-repo child of home.

Destroying published git history is forbidden: no force push, mirror push,
filter-branch, filter-repo, or reflog expiry.

A PreToolUse hook enforces these rules.
