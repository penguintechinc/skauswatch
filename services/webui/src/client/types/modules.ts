/**
 * Module registry types — reflects the response from GET /api/v1/modules.
 *
 * Each field is true when the corresponding sub-module is installed and
 * enabled on the server, false otherwise. All fields default to false until
 * the first successful fetch completes.
 */
export interface ModuleMap {
  icebox: boolean;
  checkpoint: boolean;
  darwin: boolean;
  watcher: boolean;
  guardian: boolean;
  warden: boolean;
}
