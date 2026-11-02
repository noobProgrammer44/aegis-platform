import type { Metadata } from "next";
import { Card, PageHeader } from "@/components/ui/card";
import { GradeBadge } from "@/components/ui/badges";
import type { HealthGrade } from "@/types/aegis";

export const metadata: Metadata = { title: "Help" };

const GRADES: readonly [HealthGrade, string][] = [
  ["A", "0-200"],
  ["B", "201-400"],
  ["C", "401-600"],
  ["D", "601-800"],
  ["F", "801-1000"],
];

export default function HelpPage() {
  return (
    <div className="max-w-3xl px-8 py-8">
      <PageHeader title="Help" description="How Aegis works and how to use it responsibly." />
      <div className="space-y-5">
        <Card title="Authorized use only">
          <p className="text-sm leading-relaxed text-text-dim">
            Only scan systems you own or have written permission to test. Passive checks
            (certificate transparency and DNS) work on any domain. Anything that sends traffic to
            a target needs that target to be authorized first, and every authorization is
            recorded in the audit log.
          </p>
        </Card>
        <Card title="Health score">
          <p className="text-sm leading-relaxed text-text-dim">
            Each target gets a score from 0 (best) to 1000 (worst). The most severe open risk
            sets the starting point, and more risks push the score higher. Accepted and closed
            risks don&apos;t count.
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            {GRADES.map(([grade, range]) => (
              <div key={grade} className="flex items-center gap-2 text-sm text-text-dim">
                <GradeBadge grade={grade} />
                <span className="font-mono text-xs">{range}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Risk status">
          <dl className="grid gap-3 text-sm sm:grid-cols-[120px_1fr]">
            <dt className="font-medium">Open</dt>
            <dd className="text-text-dim">The latest scan still finds it.</dd>
            <dt className="font-medium">Closed</dt>
            <dd className="text-text-dim">The latest scan of that target no longer finds it.</dd>
            <dt className="font-medium">Accepted</dt>
            <dd className="text-text-dim">
              You decided it&apos;s fine (expected, a false positive, or low priority). It stays
              visible but no longer affects the score.
            </dd>
          </dl>
        </Card>
      </div>
    </div>
  );
}
