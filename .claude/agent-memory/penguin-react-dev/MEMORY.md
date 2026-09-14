# Memory Index

- [webui lib/ gitignore trap](webui-lib-dir-gitignore-trap.md) — new files under services/webui/src/client/lib/ are silently git-ignored; use utils/ instead
- [webui TanStack Query provider missing](webui-query-provider-missing.md) — vault module uses useQuery/useMutation but no QueryClientProvider exists; use useState+useEffect for new core-app components
- [webui manager proxy + super_admin role](webui-manager-proxy-and-roles.md) — /api/* (non-vault/codescan) proxies to manager at /api/v1; super_admin is a real DB-only role, useAuth().isSuperAdmin() added
