/**
 * Runs once when the Next.js server starts. Starts the scheduler, which also resumes
 * the scan queue. Node runtime only: the scanner uses SQLite, sockets and Docker.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { startScheduler } = await import("./lib/scans/scheduler");
  startScheduler();
}
