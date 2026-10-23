# Compatibility report

## APK examined
- Package: `com.dyluc.regataonly`
- Version code/name: `904 / 904`
- Main activity: `com.dyluc.regataonly.MainActivity`
- Service: `com.dyluc.regataonly.RegataForegroundService`

## Implemented in this server
- License check at `/srv/check_license.php`.
- Signed session authentication using `X-NR-*` headers and HMAC-SHA256.
- Auto Regata actions at `/srv/backup_api/auto_regata.php`.
- Worker claim, release, and consume endpoints.
- Update-check endpoint at `/srv/regataonly_api/check_update.php`.
- Response fields `master`, `master_meta`, `job`, `logs`, and `workers` expected by the APK.
- Corrected `npm run dev` to watch the deployed `server.js` file.

## Important limitation
The APK also talks directly to Playrix Township APIs and uses account/save-city data. This server does not recreate Playrix services and cannot manufacture valid game accounts or tokens. `WORKER_POOL_JSON` must contain legitimately available worker records supplied by the owner.

## Deployment secrets
Set `LICENSE_KEYS`, `SESSION_SECRET`, and `WORKER_POOL_JSON` as private environment variables. Never commit them to GitHub.
