# Quick Share Git Deploy

This project can be deployed with a simple flow:

1. make changes locally
2. commit and push to GitHub
3. pull on the VPS
4. restart `quick-share.service`

That gives you a much cleaner update path than manually copying files every time.

## One-Time VPS Setup

Use this only once when converting the VPS folder from a manually uploaded app into a git-backed deployment.

### 1. Back up the current live folder

On the VPS:

```bash
cd ~/Projects
mv quick-share quick-share_pre_git_backup
```

### 2. Clone the repo into the live path

```bash
cd ~/Projects
git clone https://github.com/kumaark7/Quick_Share-.git quick-share
```

### 3. Restore runtime storage

Quick Share keeps runtime data in `storage/`, and that folder is intentionally ignored by git.

If you want to keep existing shares and accounts from the old live app:

```bash
mkdir -p ~/Projects/quick-share/storage
cp -a ~/Projects/quick-share_pre_git_backup/storage/. ~/Projects/quick-share/storage/
mkdir -p ~/Projects/quick-share/storage/files
```

If you do not care about old data, just create empty storage:

```bash
mkdir -p ~/Projects/quick-share/storage/files
```

### 4. Make sure the service still points to the same live path

Check:

```bash
sudo systemctl cat quick-share
```

The service should still point at:

```text
/home/ubuntu/Projects/quick-share
```

### 5. Restart the app

```bash
sudo systemctl restart quick-share
sudo systemctl status quick-share --no-pager
```

### 6. Confirm the live repo is now a real git checkout

```bash
cd ~/Projects/quick-share
git status
git remote -v
```

## Normal Update Flow

After the one-time setup, normal deploys become simple.

### Local machine

From the project folder:

```powershell
git add .
git commit -m "Describe the change"
git push origin main
```

### VPS

```bash
cd ~/Projects/quick-share
git pull --ff-only origin main
sudo systemctl restart quick-share
sudo systemctl status quick-share --no-pager
```

## Optional One-Line VPS Update

After the VPS folder is a git clone, you can update it with:

```bash
cd ~/Projects/quick-share && git pull --ff-only origin main && sudo systemctl restart quick-share && sudo systemctl status quick-share --no-pager
```

## Important Notes

- `storage/` is ignored by git on purpose.
- That means runtime shares, uploaded files, and local account data stay on the VPS.
- Do not delete `storage/` unless you want to wipe Quick Share data.
- If `git pull --ff-only` fails, it usually means there is an unexpected local edit on the VPS. In that case, check:

```bash
git status
```

## Current Best Practice

Now that the public site is available at:

```text
https://quickshare.projectdarkhope.xyz
```

the best workflow is:

- edit locally
- push to GitHub
- pull on VPS
- restart the service

