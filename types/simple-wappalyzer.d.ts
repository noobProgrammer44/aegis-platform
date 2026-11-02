declare module "simple-wappalyzer" {
  interface WappalyzerInput {
    url?: string;
    headers?: Record<string, string | string[]>;
    html?: string;
  }

  interface DetectedTechnology {
    name: string;
    version?: string;
    confidence?: number;
    categories?: { id: number; name: string }[];
  }

  function wappalyzer(input: WappalyzerInput): Promise<DetectedTechnology[]>;
  export default wappalyzer;
}
