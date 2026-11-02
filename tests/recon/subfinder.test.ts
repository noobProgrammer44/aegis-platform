import { describe, expect, it } from "vitest";
import { parseSubfinderOutput } from "@/lib/recon/subfinder";

describe("parseSubfinderOutput", () => {
  it("keeps in-scope names, lowercased, deduped and sorted", () => {
    const out = "API.example.com\napp.example.com.\napi.example.com\n\nexample.com\r\n";
    expect(parseSubfinderOutput(out, "example.com")).toEqual(["api.example.com", "app.example.com", "example.com"]);
  });

  it("drops names outside the domain and lookalikes", () => {
    const out = "evil-example.com\nexample.com.attacker.net\nwww.example.com\nbad name.example.com\n";
    expect(parseSubfinderOutput(out, "example.com")).toEqual(["www.example.com"]);
  });
});
