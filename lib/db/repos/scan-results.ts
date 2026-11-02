import type { ScanResultFile } from "@/types/aegis";
import { newId, nowIso, type DB } from "../client";

/** Raw scanner output stored with a scan (nuclei JSONL, nmap XML, ...), for download. */

interface ScanResultRow {
  id: string;
  scan_id: string;
  target_id: string | null;
  filename: string;
  content_type: string;
  size: number;
  created_at: string;
}

export interface NewScanResult {
  scanId: string;
  targetId: string | null;
  filename: string;
  contentType: string;
  content: string | Buffer;
}

const toFile = (row: ScanResultRow): ScanResultFile => ({
  id: row.id,
  scanId: row.scan_id,
  targetId: row.target_id,
  filename: row.filename,
  contentType: row.content_type,
  size: row.size,
  createdAt: row.created_at,
});

const META_COLUMNS =
  "r.id, r.scan_id, r.target_id, r.filename, r.content_type, length(r.content) AS size, r.created_at";

export function addScanResult(db: DB, input: NewScanResult): ScanResultFile {
  const content = typeof input.content === "string" ? Buffer.from(input.content) : input.content;
  const file: ScanResultFile = {
    id: newId("res"),
    scanId: input.scanId,
    targetId: input.targetId,
    filename: input.filename,
    contentType: input.contentType,
    size: content.length,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO scan_results (id, scan_id, target_id, filename, content_type, content, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(file.id, file.scanId, file.targetId, file.filename, file.contentType, content, file.createdAt);
  return file;
}

/** Result files of a scan (metadata only), scoped to the scan's workspace. */
export function listScanResults(db: DB, workspaceId: string, scanId: string): ScanResultFile[] {
  const rows = db
    .prepare(
      `SELECT ${META_COLUMNS} FROM scan_results r JOIN scans s ON s.id = r.scan_id
       WHERE s.workspace_id = ? AND r.scan_id = ? ORDER BY r.created_at, r.id`,
    )
    .all(workspaceId, scanId) as ScanResultRow[];
  return rows.map(toFile);
}

export function getScanResultContent(
  db: DB,
  workspaceId: string,
  resultId: string,
): { file: ScanResultFile; content: Buffer } | null {
  const row = db
    .prepare(
      `SELECT ${META_COLUMNS}, r.content AS content FROM scan_results r
       JOIN scans s ON s.id = r.scan_id WHERE s.workspace_id = ? AND r.id = ?`,
    )
    .get(workspaceId, resultId) as (ScanResultRow & { content: Buffer }) | undefined;
  return row ? { file: toFile(row), content: row.content } : null;
}
