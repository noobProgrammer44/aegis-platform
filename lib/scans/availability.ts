import { ZAP_IMAGE } from "./checks/zap";
import { DOCKER_SCANNERS } from "./catalog";
import { dockerAvailable, dockerImagePresent } from "./tools";

/** Scanners that can't run right now, with the reason (shown in the New scan dialog). */
export async function unavailableScanners(): Promise<Record<string, string>> {
  if (!(await dockerAvailable())) {
    return Object.fromEntries(DOCKER_SCANNERS.map((type) => [type, "Docker isn't running"]));
  }
  return (await dockerImagePresent(ZAP_IMAGE))
    ? {}
    : { ZAP_PASSIVE: `Run: docker pull ${ZAP_IMAGE}`, ZAP_ACTIVE: `Run: docker pull ${ZAP_IMAGE}` };
}
