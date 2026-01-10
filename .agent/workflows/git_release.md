---
description: Git Release Cycle: Check, Tag, Commit, Push
---

This workflow automates the process of checking status, tagging a new version, committing, and pushing code.

## Versioning Strategy
The version format is **v a.b.c**:
- **a** (Major): Major updates or breaking changes.
- **b** (Minor): Minor updates or new features.
- **c** (Patch): Error or bug fixes.

## Procedure

1. **Check Git Status**
   Review the current changes to ensure everything is ready for the release.
   // turbo
   ```powershell
   git status
   ```

2. **Determine Version & Commit Message**
   - Review the `git status` output.
   - **Action**: Ask the USER for the next version number (based on the strategy above) and the commit message.

3. **Stage and Commit**
   Once the user provides the message, run the following (replace `[MESSAGE]` with the actual message):
   ```powershell
   git add .
   git commit -m "[MESSAGE]"
   ```

4. **Tag the Release**
   Apply the tag using the version provided by the user (replace `[VERSION]` with `v1.2.3` etc).
   ```powershell
   git tag [VERSION]
   ```

5. **Push to Remote**
   Push both the changes and the new tag.
   ```powershell
   git push origin main
   git push origin [VERSION]
   ```

6. **Verify**
   // turbo
   ```powershell
   git status
   ```
