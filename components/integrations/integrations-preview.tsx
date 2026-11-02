"use client";

import { Bell, Cloud, CloudCog, Mail, MessageSquare, MessagesSquare, Ticket, Webhook, type LucideIcon } from "lucide-react";
import { useState } from "react";
import { Chip } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/overlays";
import { SEGMENT_FRAME, segmentClass } from "@/components/ui/segmented";

/**
 * Integrations PREVIEW. Static mock of the integrations screen: the dialogs show what
 * each integration will ask for, but nothing is saved, stored or sent anywhere.
 */

type Field = { label: string; placeholder: string; type?: "text" | "password" | "url" | "email" };

interface Integration {
  id: string;
  name: string;
  category: "Alerts" | "Ticketing" | "Developer" | "Cloud import";
  icon: LucideIcon;
  description: string;
  fields: Field[];
  events?: boolean;
  policy?: boolean;
}

const EVENTS = ["Scan finished", "Scan failed", "New risk found", "Risk closed", "Report created"];

const INTEGRATIONS: readonly Integration[] = [
  { id: "email", name: "Email alerts", category: "Alerts", icon: Mail, description: "Email a summary after scheduled scans and when new risks appear.", fields: [{ label: "Recipients", placeholder: "security@yourcompany.com, cto@yourcompany.com", type: "email" }, { label: "SMTP server", placeholder: "smtp.yourcompany.com:587" }], policy: true },
  { id: "slack", name: "Slack", category: "Alerts", icon: MessageSquare, description: "Post scan results and new critical risks to a channel.", fields: [{ label: "Incoming webhook URL", placeholder: "https://hooks.slack.com/services/…", type: "url" }, { label: "Channel", placeholder: "#security-alerts" }], events: true },
  { id: "teams", name: "Microsoft Teams", category: "Alerts", icon: MessagesSquare, description: "Send the same alerts to a Teams channel.", fields: [{ label: "Workflow webhook URL", placeholder: "https://…logic.azure.com/…", type: "url" }], events: true },
  { id: "pagerduty", name: "PagerDuty", category: "Alerts", icon: Bell, description: "Page the on-call engineer when a critical risk is found.", fields: [{ label: "Integration key", placeholder: "32-character routing key", type: "password" }] },
  { id: "webhook", name: "Webhooks", category: "Developer", icon: Webhook, description: "Signed JSON events to your own endpoint, with a delivery log.", fields: [{ label: "Endpoint URL", placeholder: "https://api.yourcompany.com/aegis-events", type: "url" }, { label: "Signing secret", placeholder: "Generated when saved", type: "password" }], events: true },
  { id: "jira", name: "Jira", category: "Ticketing", icon: Ticket, description: "Open a ticket for each new high or critical risk.", fields: [{ label: "Site URL", placeholder: "https://yourcompany.atlassian.net", type: "url" }, { label: "Project key", placeholder: "SEC" }, { label: "Account email", placeholder: "bot@yourcompany.com", type: "email" }, { label: "API token", placeholder: "Atlassian API token", type: "password" }] },
  { id: "aws", name: "AWS import", category: "Cloud import", icon: Cloud, description: "Import public IPs, load balancers and Route 53 domains as targets.", fields: [{ label: "Role ARN", placeholder: "arn:aws:iam::123456789012:role/aegis-readonly" }, { label: "Regions", placeholder: "us-east-1, eu-west-1" }] },
  { id: "azure", name: "Azure import", category: "Cloud import", icon: CloudCog, description: "Import public IPs and DNS zones from a subscription.", fields: [{ label: "Tenant ID", placeholder: "00000000-0000-0000-0000-000000000000" }, { label: "Subscription ID", placeholder: "00000000-0000-0000-0000-000000000000" }] },
];

const FIELD = "w-full rounded-lg border border-border bg-control px-3 py-2 text-sm placeholder:text-text-faint focus:border-accent/60 focus:outline-none";

function ConfigureDialog({ integration, onClose }: { integration: Integration; onClose: () => void }) {
  const [policy, setPolicy] = useState("ON_CHANGES");
  return (
    <Modal
      open
      onClose={onClose}
      title={`Configure ${integration.name}`}
      footer={
        <>
          <span className="mr-auto self-center text-xs text-caution">Preview: saving isn&apos;t connected yet.</span>
          <Button variant="ghost" onClick={onClose}>Close</Button>
          <Button variant="secondary" disabled>Send test</Button>
          <Button variant="primary" disabled>Save</Button>
        </>
      }
    >
      <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
        <p className="text-sm text-text-dim">{integration.description}</p>
        {integration.fields.map((f) => (
          <label key={f.label} className="block text-sm">
            <span className="mb-1.5 block font-medium">{f.label}</span>
            <input type={f.type ?? "text"} placeholder={f.placeholder} autoComplete="off" className={FIELD} />
          </label>
        ))}
        {integration.policy && (
          <div>
            <span className="mb-1.5 block text-sm font-medium">Send emails</span>
            <div className={SEGMENT_FRAME + " w-fit"} role="radiogroup" aria-label="Send emails">
              {[["NEVER", "Never"], ["ON_CHANGES", "When risks change"], ["ALWAYS", "After every scan"]].map(([value, label]) => (
                <button key={value} type="button" role="radio" aria-checked={policy === value} className={segmentClass(policy === value)} onClick={() => setPolicy(value)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
        )}
        {integration.events && (
          <fieldset>
            <legend className="mb-1.5 text-sm font-medium">Events</legend>
            <div className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
              {EVENTS.map((e) => (
                <label key={e} className="flex items-center gap-1.5"><input type="checkbox" defaultChecked={e !== "Report created"} /> {e}</label>
              ))}
            </div>
          </fieldset>
        )}
      </form>
    </Modal>
  );
}

export function IntegrationsPreview() {
  const [open, setOpen] = useState<Integration | null>(null);
  const categories = [...new Set(INTEGRATIONS.map((i) => i.category))];
  return (
    <div className="space-y-8">
      <div role="note" className="rounded-xl border border-caution-border bg-caution-bg px-4 py-3 text-sm text-caution">
        <span className="font-medium">Preview.</span> Integrations aren&apos;t connected yet. You can look through the
        setup screens, but nothing here is saved, stores credentials or sends data.
      </div>
      {categories.map((category) => (
        <section key={category}>
          <h2 className="mb-3 font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint">{category}</h2>
          <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
            {INTEGRATIONS.filter((i) => i.category === category).map((i) => {
              const Icon = i.icon;
              return (
                <div key={i.id} className="anim-rise flex flex-col rounded-2xl border border-border bg-surface/90 p-5 backdrop-blur-sm transition-colors hover:border-accent/40">
                  <div className="flex items-start justify-between gap-3">
                    <span className="grid h-10 w-10 place-items-center rounded-xl border border-border bg-surface-raised text-accent">
                      <Icon className="h-5 w-5" />
                    </span>
                    <Chip>Preview</Chip>
                  </div>
                  <h3 className="mt-4 font-medium">{i.name}</h3>
                  <p className="mt-1 flex-1 text-sm leading-relaxed text-text-dim">{i.description}</p>
                  <div className="mt-4 flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-xs text-text-faint">
                      <span className="h-1.5 w-1.5 rounded-full bg-text-ghost" /> Not connected
                    </span>
                    <Button size="sm" onClick={() => setOpen(i)}>Configure</Button>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      ))}
      {open && <ConfigureDialog key={open.id} integration={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
